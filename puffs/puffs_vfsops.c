/*	$NetBSD: puffs_vfsops.c,v 1.82 2009/03/18 10:22:42 cegger Exp $	*/

/*
 * Copyright (c) 2005, 2006  Antti Kantee.  All Rights Reserved.
 *
 * Development of this software was supported by the
 * Google Summer of Code program and the Ulla Tuominen Foundation.
 * The Google SoC project was mentored by Bill Studenmund.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
/*
__KERNEL_RCSID(0, "$NetBSD: puffs_vfsops.c,v 1.82 2009/03/18 10:22:42 cegger Exp $");
*/

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/malloc.h>
#include <sys/extattr.h>
#include <sys/queue.h>
#include <sys/vnode.h>
#include <sys/dirent.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include <putter_sys.h>

#include <puffs_msgif.h>
#include <puffs_sys.h>

#include <sys/libkern.h>

#include <nfs/nfsproto.h> /* for fh sizes */

#ifndef PUFFS_PNODEBUCKETS
#define PUFFS_PNODEBUCKETS 256
#endif
#ifndef PUFFS_MAXPNODEBUCKETS
#define PUFFS_MAXPNODEBUCKETS 8192
#endif
int puffs_pnodebuckets_default = PUFFS_PNODEBUCKETS;
int puffs_maxpnodebuckets = PUFFS_MAXPNODEBUCKETS;

#define BUCKETALLOC(a) (sizeof(struct puffs_pnode_hashlist *) * (a))

static struct putter_ops puffs_putter = {
	.pop_getout	= puffs_msgif_getout,
	.pop_releaseout	= puffs_msgif_releaseout,
	.pop_waitcount	= puffs_msgif_waitcount,
	.pop_dispatch	= puffs_msgif_dispatch,
	.pop_close	= puffs_msgif_close,
};

static const char *puffs_opts[] = {
	"puffs_args", NULL
};

static int
puffs_vfsop_mount(struct mount *mp)
{
	struct puffs_mount *pmp = NULL;
	struct puffs_kargs _args_data;
	struct puffs_kargs *args = &_args_data;
	char fstype[MFSNAMELEN];
	char *p;
	int error = 0, i;
	pid_t mntpid = curthread->td_proc->p_pid;

	if (vfs_filteropt(mp->mnt_optnew, puffs_opts))
		return EINVAL;

	error = vfs_copyopt(mp->mnt_optnew, "puffs_args", &_args_data, sizeof(_args_data));
	if (error)
		return EINVAL;

	/* update is not supported currently */
	if (mp->mnt_flag & MNT_UPDATE)
		return EOPNOTSUPP;

	/* devel phase */
	if (args->pa_vers != (PUFFSVERSION | PUFFSDEVELVERS)) {
		printf("puffs_mount: development version mismatch: "
		    "kernel %d, lib %d\n",
		    PUFFSVERSION, args->pa_vers & ~PUFFSDEVELVERS);
		error = EINVAL;
		goto out;
	}

	if ((args->pa_flags & ~PUFFS_KFLAG_MASK) != 0) {
		printf("puffs_mount: invalid KFLAGs 0x%x\n", args->pa_flags);
		error = EINVAL;
		goto out;
	}
	if ((args->pa_fhflags & ~PUFFS_FHFLAG_MASK) != 0) {
		printf("puffs_mount: invalid FHFLAGs 0x%x\n", args->pa_fhflags);
		error = EINVAL;
		goto out;
	}

	/* use dummy value for passthrough */
	if (args->pa_fhflags & PUFFS_FHFLAG_PASSTHROUGH)
		args->pa_fhsize = MAXFIDSZ;

	/* sanitize file handle length */
	if (PUFFS_TOFHSIZE(args->pa_fhsize) > sizeof(struct fid)) {
		printf("puffs_mount: handle size %zu too large\n",
		    args->pa_fhsize);
		error = EINVAL;
		goto out;
	}
	/* sanity check file handle max sizes */
	if (args->pa_fhsize && args->pa_fhflags & PUFFS_FHFLAG_PROTOMASK) {
		size_t kfhsize = PUFFS_TOFHSIZE(args->pa_fhsize);

		if (args->pa_fhflags & PUFFS_FHFLAG_NFSV2) {
			if (kfhsize > NFSX_FH(0)) {
				printf("puffs_mount: fhsize larger than "
				    "NFSv2 max %d\n",
				    PUFFS_FROMFHSIZE(NFSX_V2FH));
				error = EINVAL;
				goto out;
			}
		}

		if (args->pa_fhflags & PUFFS_FHFLAG_NFSV3) {
			if (kfhsize > NFSX_FH(1)) {
				printf("puffs_mount: fhsize larger than "
				    "NFSv3 max %d\n",
				    PUFFS_FROMFHSIZE(NFSX_V3FHMAX));
				error = EINVAL;
				goto out;
			}
		}
	}

	/* don't allow non-printing characters (like my sweet umlauts.. snif) */
	args->pa_typename[sizeof(args->pa_typename)-1] = '\0';
	for (p = args->pa_typename; *p; p++)
		if (*p < ' ' || *p > '~')
			*p = '.';

	args->pa_mntfromname[sizeof(args->pa_mntfromname)-1] = '\0';
	for (p = args->pa_mntfromname; *p; p++)
		if (*p < ' ' || *p > '~')
			*p = '.';

	/* build real name */
	(void)strlcpy(fstype, PUFFS_TYPEPREFIX, sizeof(fstype));
	(void)strlcat(fstype, args->pa_typename, sizeof(fstype));

	/* inform user server if it got the max request size it wanted */
	if (args->pa_maxmsglen == 0 || args->pa_maxmsglen > PUFFS_MSG_MAXSIZE)
		args->pa_maxmsglen = PUFFS_MSG_MAXSIZE;
	else if (args->pa_maxmsglen < 2*PUFFS_MSGSTRUCT_MAX)
		args->pa_maxmsglen = 2*PUFFS_MSGSTRUCT_MAX;

	(void)strlcpy(args->pa_typename, fstype, sizeof(args->pa_typename));

	if (args->pa_nhashbuckets == 0)
		args->pa_nhashbuckets = puffs_pnodebuckets_default;
	if (args->pa_nhashbuckets < 1)
		args->pa_nhashbuckets = 1;
	if (args->pa_nhashbuckets > PUFFS_MAXPNODEBUCKETS) {
		args->pa_nhashbuckets = puffs_maxpnodebuckets;
		printf("puffs_mount: using %d hash buckets. "
		    "adjust puffs_maxpnodebuckets for more\n",
		    puffs_maxpnodebuckets);
	}

	mp->mnt_stat.f_namemax = MAXNAMLEN;

	pmp = malloc(sizeof(struct puffs_mount), M_PUFFS, M_WAITOK | M_ZERO);

	MNT_ILOCK(mp);
	mp->mnt_flag &= ~MNT_LOCAL; /* we don't really know, so ... */
	mp->mnt_kern_flag |= MNTK_MPSAFE;
	MNT_IUNLOCK(mp);

	pmp->pmp_status = PUFFSTAT_MOUNTING;
	pmp->pmp_mp = mp;
	pmp->pmp_msg_maxsize = args->pa_maxmsglen;
	pmp->pmp_args = *args;

	pmp->pmp_npnodehash = args->pa_nhashbuckets;
	pmp->pmp_pnodehash = malloc(BUCKETALLOC(pmp->pmp_npnodehash), M_PUFFS, M_WAITOK);
	for (i = 0; i < pmp->pmp_npnodehash; i++)
		LIST_INIT(&pmp->pmp_pnodehash[i]);
	LIST_INIT(&pmp->pmp_newcookie);

	/*
	 * Inform the fileops processing code that we have a mountpoint.
	 * If it doesn't know about anyone with our pid/fd having the
	 * device open, punt
	 */
	if ((pmp->pmp_pi
	    = putter_attach(mntpid, args->pa_fd, pmp, &puffs_putter)) == NULL) {
		error = ENOENT;
		goto out;
	}

	/* XXX: check parameters */
	pmp->pmp_root_cookie = args->pa_root_cookie;
	pmp->pmp_root_vtype = args->pa_root_vtype;
	pmp->pmp_root_vsize = args->pa_root_vsize;
	pmp->pmp_root_rdev = args->pa_root_rdev;

	mtx_init(&pmp->pmp_lock, "puffs pmp_lock", NULL, MTX_DEF);
	cv_init(&pmp->pmp_msg_waiter_cv, "puffsget");
	cv_init(&pmp->pmp_refcount_cv, "puffsref");
	cv_init(&pmp->pmp_unmounting_cv, "puffsum");
	TAILQ_INIT(&pmp->pmp_msg_touser);
	TAILQ_INIT(&pmp->pmp_msg_replywait);

	DPRINTF(("puffs_mount: mount point at %p, puffs specific at %p\n",
	    mp, MPTOPUFFSMP(mp)));

	mp->mnt_data = pmp;
	vfs_getnewfsid(mp);
	vfs_mountedfrom(mp, args->pa_mntfromname);

 out:
	if (error && pmp && pmp->pmp_pnodehash)
		free(pmp->pmp_pnodehash, M_PUFFS);
	if (error && pmp)
		free(pmp, M_PUFFS);

	return error;
}

static int
puffs_vfsop_unmount(struct mount *mp, int mntflags)
{
	PUFFS_MSG_VARS(vfs, unmount);
	struct puffs_mount *pmp;
	int error, force;

	error = 0;
	force = mntflags & MNT_FORCE;
	pmp = MPTOPUFFSMP(mp);

	DPRINTF(("puffs_unmount: detach filesystem from vfs, current "
	    "status 0x%x\n", pmp->pmp_status));

	/*
	 * flush all the vnodes.  VOP_RECLAIM() takes care that the
	 * root vnode does not get flushed until unmount.  The
	 * userspace root node cookie is stored in the mount
	 * structure, so we can always re-instantiate a root vnode,
	 * should userspace unmount decide it doesn't want to
	 * cooperate.
	 */
	error = vflush(mp, 0, force ? FORCECLOSE : 0, curthread);
	if (error)
		goto out;

	/*
	 * If we are not DYING, we should ask userspace's opinion
	 * about the situation
	 */
	mtx_lock(&pmp->pmp_lock);
	if (pmp->pmp_status != PUFFSTAT_DYING) {
		pmp->pmp_unmounting = 1;
		mtx_unlock(&pmp->pmp_lock);

		PUFFS_MSG_ALLOC(vfs, unmount);
		puffs_msg_setinfo(park_unmount,
		    PUFFSOP_VFS, PUFFS_VFS_UNMOUNT, NULL);
		unmount_msg->pvfsr_flags = mntflags;

		PUFFS_MSG_ENQUEUEWAIT(pmp, park_unmount, error);
		PUFFS_MSG_RELEASE(unmount);

		error = checkerr(pmp, error, __func__);
		DPRINTF(("puffs_unmount: error %d force %d\n", error, force));

		mtx_lock(&pmp->pmp_lock);
		pmp->pmp_unmounting = 0;
		cv_broadcast(&pmp->pmp_unmounting_cv);
	}

	/*
	 * if userspace cooperated or we really need to die,
	 * screw what userland thinks and just die.
	 */
	if (error == 0 || force) {
		/* tell waiters & other resources to go unwait themselves */
		puffs_userdead(pmp);
		mtx_unlock(&pmp->pmp_lock);
		putter_detach(pmp->pmp_pi);

		/*
		 * Wait until there are no more users for the mount resource.
		 * Notice that this is hooked against transport_close
		 * and return from touser.  In an ideal world, it would
		 * be hooked against final return from all operations.
		 * But currently it works well enough, since nobody
		 * does weird blocking voodoo after return from touser().
		 */
		mtx_lock(&pmp->pmp_lock);
		while (pmp->pmp_refcount != 0)
			cv_wait(&pmp->pmp_refcount_cv, &pmp->pmp_lock);
		mtx_unlock(&pmp->pmp_lock);

		/* free resources now that we hopefully have no waiters left */
		cv_destroy(&pmp->pmp_unmounting_cv);
		cv_destroy(&pmp->pmp_refcount_cv);
		cv_destroy(&pmp->pmp_msg_waiter_cv);
		mtx_destroy(&pmp->pmp_lock);

		free(pmp->pmp_pnodehash, M_PUFFS);
		free(pmp, M_PUFFS);
		error = 0;
	} else {
		mtx_unlock(&pmp->pmp_lock);
	}

 out:
	DPRINTF(("puffs_unmount: return %d\n", error));
	return error;
}

/*
 * This doesn't need to travel to userspace
 */
static int
puffs_vfsop_root(struct mount *mp, int flags, struct vnode **vpp)
{
	struct puffs_mount *pmp = MPTOPUFFSMP(mp);
	int rv;


	rv = puffs_cookie2vnode(pmp, pmp->pmp_root_cookie, flags, 1, vpp);
	KASSERT(rv != PUFFS_NOSUCHCOOKIE, ("rv != PUFFS_NOSUCHCOOKIE"));


	if (rv == 0) {
		/* FreeBSD lacks vfs_start */
		mtx_lock(&pmp->pmp_lock);
		if (pmp->pmp_status == PUFFSTAT_MOUNTING)
			pmp->pmp_status = PUFFSTAT_RUNNING;
		mtx_unlock(&pmp->pmp_lock);
	}

	return rv;
}

static int
puffs_vfsop_statfs(struct mount *mp, struct statfs *sbp)
{
	PUFFS_MSG_VARS(vfs, statvfs);
	struct puffs_mount *pmp;
	int error = 0;

	pmp = MPTOPUFFSMP(mp);

	/*
	 * If we are mounting, it means that the userspace counterpart
	 * is calling mount(2), but mount(2) also calls statvfs.  So
	 * requesting statvfs from userspace would mean a deadlock.
	 * Compensate.
	 */
	if (pmp->pmp_status == PUFFSTAT_MOUNTING)
		return EINPROGRESS;

	PUFFS_MSG_ALLOC(vfs, statvfs);
	puffs_msg_setinfo(park_statvfs, PUFFSOP_VFS, PUFFS_VFS_STATVFS, NULL);

	PUFFS_MSG_ENQUEUEWAIT(pmp, park_statvfs, error);
	error = checkerr(pmp, error, __func__);
	statvfs_msg->pvfsr_sb.f_iosize = DEV_BSIZE;

	/*
	 * Try to produce a sensible result even in the event
	 * of userspace error.
	 *
	 * XXX: cache the copy in non-error case
	 */
	if (!error) {
		struct statfs *rsbp = &statvfs_msg->pvfsr_sb;

		sbp->f_flags = rsbp->f_flags;
		sbp->f_bsize = rsbp->f_bsize;
		sbp->f_iosize = rsbp->f_iosize;
		sbp->f_blocks = rsbp->f_blocks;
		sbp->f_bfree = rsbp->f_bfree;
		sbp->f_bavail = rsbp->f_bavail;
		sbp->f_files = rsbp->f_files;
		sbp->f_ffree = rsbp->f_ffree;
	} else {
		sbp->f_flags = 0;
		sbp->f_bsize = DEV_BSIZE;
		sbp->f_iosize = DEV_BSIZE;
		sbp->f_blocks = 2;
		sbp->f_bfree = 0;
		sbp->f_bavail = 0;
		sbp->f_files = 1;
		sbp->f_ffree = 0;
	}

	PUFFS_MSG_RELEASE(statvfs);
	return error;
}

static int
puffs_vfsop_sync(struct mount *mp, int waitfor)
{
	PUFFS_MSG_VARS(vfs, sync);
	struct puffs_mount *pmp = MPTOPUFFSMP(mp);
	int error, rv;

	error = vfs_stdsync(mp, waitfor);

	/* sync fs */
	PUFFS_MSG_ALLOC(vfs, sync);
	sync_msg->pvfsr_waitfor = waitfor;
	puffs_credcvt(&sync_msg->pvfsr_cred, curthread->td_ucred);
	puffs_msg_setinfo(park_sync, PUFFSOP_VFS, PUFFS_VFS_SYNC, NULL);

	PUFFS_MSG_ENQUEUEWAIT(pmp, park_sync, rv);
	rv = checkerr(pmp, rv, __func__);
	if (rv)
		error = rv;

	PUFFS_MSG_RELEASE(sync);
	return error;
}

static int
puffs_vfsop_fhtovp(struct mount *mp, struct fid *fhp, struct vnode **vpp)
{
	PUFFS_MSG_VARS(vfs, fhtonode);
	struct puffs_mount *pmp = MPTOPUFFSMP(mp);
	struct vnode *vp;
	void *fhdata;
	size_t argsize, fhlen;
	int error;

	if (pmp->pmp_args.pa_fhsize == 0)
		return EOPNOTSUPP;

	if (pmp->pmp_args.pa_fhflags & PUFFS_FHFLAG_PASSTHROUGH) {
		fhlen = fhp->fid_len;
		fhdata = fhp;
	} else {
		fhlen = PUFFS_FROMFHSIZE(fhp->fid_len);
		fhdata = fhp->fid_data;

		if (pmp->pmp_args.pa_fhflags & PUFFS_FHFLAG_DYNAMIC) {
			if (pmp->pmp_args.pa_fhsize < fhlen)
				return EINVAL;
		} else {
			if (pmp->pmp_args.pa_fhsize != fhlen)
				return EINVAL;
		}
	}

	argsize = sizeof(struct puffs_vfsmsg_fhtonode) + fhlen;
	puffs_msgmem_alloc(argsize, &park_fhtonode, (void *)&fhtonode_msg, 1);
	fhtonode_msg->pvfsr_dsize = fhlen;
	memcpy(fhtonode_msg->pvfsr_data, fhdata, fhlen);
	puffs_msg_setinfo(park_fhtonode, PUFFSOP_VFS, PUFFS_VFS_FHTOVP, NULL);

	PUFFS_MSG_ENQUEUEWAIT(pmp, park_fhtonode, error);
	error = checkerr(pmp, error, __func__);
	if (error)
		goto out;

	error = puffs_cookie2vnode(pmp, fhtonode_msg->pvfsr_fhcookie, LK_EXCLUSIVE, 1, &vp);
	DPRINTF(("puffs_fhtovp: got cookie %p, existing vnode %p\n",
	    fhtonode_msg->pvfsr_fhcookie, vp));
	if (error == PUFFS_NOSUCHCOOKIE) {
		error = puffs_getvnode(mp, fhtonode_msg->pvfsr_fhcookie,
		    fhtonode_msg->pvfsr_vtype, fhtonode_msg->pvfsr_size,
		    fhtonode_msg->pvfsr_rdev, LK_EXCLUSIVE, &vp);
		if (error)
			goto out;
	} else if (error) {
		goto out;
	}

	*vpp = vp;
 out:
	puffs_msgmem_release(park_fhtonode);
	return error;
}

static int
puffs_vfsop_init(struct vfsconf *vfsp)
{

	/* some checks depend on this */
#ifdef XXX_TS
	KASSERT(VNOVAL == VSIZENOTSET, ("VNOVAL == VSIZENOTSET"));
#endif

	puffs_pnpool = uma_zcreate("puffpnpl", sizeof(struct puffs_node),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_ZINIT);
	puffs_msgif_init();

	return (0);
}

static int
puffs_vfsop_uninit(struct vfsconf *vfsp)
{

	puffs_msgif_destroy();
	uma_zdestroy(puffs_pnpool);

	return (0);
}

static struct vfsops puffs_vfsops = {
	.vfs_mount =	puffs_vfsop_mount,
	.vfs_unmount =	puffs_vfsop_unmount,
	.vfs_root =	puffs_vfsop_root,
	.vfs_statfs =	puffs_vfsop_statfs,
	.vfs_sync =	puffs_vfsop_sync,
	.vfs_fhtovp =	puffs_vfsop_fhtovp,
	.vfs_init =	puffs_vfsop_init,
	.vfs_uninit =	puffs_vfsop_uninit,
};

VFS_SET(puffs_vfsops, puffs, VFCF_NETWORK);
MODULE_DEPEND(puffs, putter, 1, 1, 1);

