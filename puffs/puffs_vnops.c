/*	$NetBSD: puffs_vnops.c,v 1.131 2008/11/26 20:17:33 pooka Exp $	*/

/*
 * Copyright (c) 2005, 2006, 2007  Antti Kantee.  All Rights Reserved.
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
__KERNEL_RCSID(0, "$NetBSD: puffs_vnops.c,v 1.131 2008/11/26 20:17:33 pooka Exp $");
*/

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/sf_buf.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/buf.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vm_extern.h>

#include <puffs_msgif.h>
#include <puffs_sys.h>

#define ERROUT(err)							\
do {									\
	error = err;							\
	goto out;							\
} while (/*CONSTCOND*/0)

static int callremove(struct puffs_mount *, puffs_cookie_t, puffs_cookie_t,
			    struct componentname *);
static int callrmdir(struct puffs_mount *, puffs_cookie_t, puffs_cookie_t,
			   struct componentname *);
static void callinactive(struct puffs_mount *, puffs_cookie_t, int);
static void callreclaim(struct puffs_mount *, puffs_cookie_t);

#define PUFFS_ABORT_LOOKUP	1
#define PUFFS_ABORT_CREATE	2
#define PUFFS_ABORT_MKNOD	3
#define PUFFS_ABORT_MKDIR	4
#define PUFFS_ABORT_SYMLINK	5

#define PUFFS_LOCKVNODE(a, l, e)					\
do {									\
	if (puffs_lockvnode((a), (l)) != 0 && (e) != 0)			\
		e = EBADF;						\
} while(/*CONSTCOND*/0)

/*
 * Press the pani^Wabort button!  Kernel resource allocation failed.
 */
static void
puffs_abortbutton(struct puffs_mount *pmp, int what,
	puffs_cookie_t dck, puffs_cookie_t ck, struct componentname *cnp)
{
	KASSERT(pmp != NULL, ("pmp == NULL"));

	switch (what) {
	case PUFFS_ABORT_CREATE:
	case PUFFS_ABORT_MKNOD:
	case PUFFS_ABORT_SYMLINK:
		callremove(pmp, dck, ck, cnp);
		break;
	case PUFFS_ABORT_MKDIR:
		callrmdir(pmp, dck, ck, cnp);
		break;
	}

	callinactive(pmp, ck, 0);
	callreclaim(pmp, ck);
}

/*
 * Begin vnode operations.
 *
 * A word from the keymaster about locks: generally we don't want
 * to use the vnode locks at all: it creates an ugly dependency between
 * the userlandia file server and the kernel.  But we'll play along with
 * the kernel vnode locks for now.  However, even currently we attempt
 * to release locks as early as possible.  This is possible for some
 * operations which a) don't need a locked vnode after the userspace op
 * and b) return with the vnode unlocked.  Theoretically we could
 * unlock-do op-lock for others and order the graph in userspace, but I
 * don't want to think of the consequences for the time being.
 */

static int
puffs_vnop_vptofh(struct vop_vptofh_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct fid *fhp = ap->a_fhp;
	PUFFS_MSG_VARS(vfs, nodetofh);
	struct puffs_node *pn = VPTOPP(vp);
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	size_t argsize, fhlen;
	int error, ltype;

	if (pmp->pmp_args.pa_fhsize == 0)
		return EOPNOTSUPP;

	fhlen = pmp->pmp_args.pa_fhsize;
	argsize = sizeof(struct puffs_vfsmsg_nodetofh) + fhlen;
	puffs_msgmem_alloc(argsize, &park_nodetofh, (void *)&nodetofh_msg, 1);
	nodetofh_msg->pvfsr_fhcookie = VPTOPNC(vp);
	nodetofh_msg->pvfsr_dsize = fhlen;
	puffs_msg_setinfo(park_nodetofh, PUFFSOP_VFS, PUFFS_VFS_VPTOFH, NULL);

	puffs_msg_enqueue(pmp, park_nodetofh);
	puffs_unlockvnode(pn, &ltype);
	error = puffs_msg_wait(pmp, park_nodetofh);
	error = checkerr(pmp, error, __func__);
	PUFFS_LOCKVNODE(pn, ltype, error);

	if (pmp->pmp_args.pa_fhflags & PUFFS_FHFLAG_PASSTHROUGH)
		fhlen = nodetofh_msg->pvfsr_dsize;
	else if (pmp->pmp_args.pa_fhflags & PUFFS_FHFLAG_DYNAMIC)
		fhlen = PUFFS_TOFHSIZE(nodetofh_msg->pvfsr_dsize);
	else
		fhlen = PUFFS_TOFHSIZE(pmp->pmp_args.pa_fhsize);

	if (fhlen > /* MAXFIDSZ */ sizeof(struct fid)) {
		puffs_senderr(pmp, PUFFS_ERR_VPTOFH, E2BIG,
		    "file handle too big", VPTOPNC(vp));
		error = EPROTO;
		goto out;
	}

	if (pmp->pmp_args.pa_fhflags & PUFFS_FHFLAG_PASSTHROUGH) {
		memcpy(fhp, nodetofh_msg->pvfsr_data, fhlen);
	} else {
		fhp->fid_len = fhlen;
		memcpy(fhp->fid_data, nodetofh_msg->pvfsr_data,
		    nodetofh_msg->pvfsr_dsize);
	}

 out:
	puffs_msgmem_release(park_nodetofh);
	return error;
}

static int
puffs_vnop_lookup(struct vop_lookup_args *ap)
{

	PUFFS_MSG_VARS(vn, lookup);
	struct puffs_mount *pmp;
	struct componentname *cnp;
	struct vnode *vp, *dvp;
	struct puffs_node *dpn;
	int dltype;
	int isdot;
	int error;

	pmp = MPTOPUFFSMP(ap->a_dvp->v_mount);
	cnp = ap->a_cnp;
	dvp = ap->a_dvp;
	dpn = dvp->v_data;
	*ap->a_vpp = NULL;

	/* r/o fs?  we check create later to handle EEXIST */
	if ((cnp->cn_flags & ISLASTCN)
	    && (dvp->v_mount->mnt_flag & MNT_RDONLY)
	    && (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME))
		return EROFS;

	isdot = cnp->cn_namelen == 1 && *cnp->cn_nameptr == '.';

	DPRINTF(("puffs_lookup: \"%s\", parent vnode %p, op: %lx\n",
	    cnp->cn_nameptr, dvp, cnp->cn_nameiop));

	/*
	 * Check if someone fed it into the cache
	 */
	if (PUFFS_USE_NAMECACHE(pmp)) {
		error = cache_lookup(dvp, ap->a_vpp, cnp);

		if (error == -1) {
			return 0;
		}
		if (error == ENOENT) {
			return error;
		}
	}

	if (isdot) {
		vp = ap->a_dvp;
		vref(vp);
		*ap->a_vpp = vp;
		return 0;
	}

	PUFFS_MSG_ALLOC(vn, lookup);
	puffs_makecn(&lookup_msg->pvnr_cn, &lookup_msg->pvnr_cn_cred,
	    cnp, PUFFS_USE_FULLPNBUF(pmp));

	puffs_msg_setinfo(park_lookup, PUFFSOP_VN,
	    PUFFS_VN_LOOKUP, VPTOPNC(dvp));

	puffs_msg_enqueue(pmp, park_lookup);
	puffs_unlockvnode(dpn, &dltype);
	error = puffs_msg_wait2(pmp, park_lookup, dpn, NULL);
	DPRINTF(("puffs_lookup: return of the userspace, part %d\n", error));
	if (puffs_lockvnode(dpn, dltype) && !error) {
		error = ENOENT;
		goto out;
	}

	/*
	 * In case of error, there is no new vnode to play with, so be
	 * happy with the NULL value given to vpp in the beginning.
	 * Also, check if this really was an error or the target was not
	 * present.  Either treat it as a non-error for CREATE/RENAME or
	 * enter the component into the negative name cache (if desired).
	 */
	if (error) {
		error = checkerr(pmp, error, __func__);
		if (error == ENOENT) {
			/* don't allow to create files on r/o fs */
			if ((dvp->v_mount->mnt_flag & MNT_RDONLY)
			    && cnp->cn_nameiop == CREATE) {
				error = EROFS;

			/* adjust values if we are creating */
			} else if ((cnp->cn_flags & ISLASTCN)
			    && (cnp->cn_nameiop == CREATE
			      || cnp->cn_nameiop == RENAME)) {
				cnp->cn_flags |= SAVENAME;
				error = EJUSTRETURN;

			/* save negative cache entry */
			} else {
				if ((cnp->cn_flags & MAKEENTRY)
				    && PUFFS_USE_NAMECACHE(pmp))
					cache_enter(dvp, NULL, cnp);
			}
		}
		goto out;
	}

	/*
	 * Check that we don't get our parent node back, that would cause
	 * a pretty obvious deadlock.
	 */
	if (lookup_msg->pvnr_newnode == dpn->pn_cookie) {
		puffs_senderr(pmp, PUFFS_ERR_LOOKUP, EINVAL,
		    "lookup produced parent cookie", lookup_msg->pvnr_newnode);
		error = EPROTO;
		goto out;
	}

	error = puffs_cookie2vnode(pmp, lookup_msg->pvnr_newnode, LK_EXCLUSIVE, 1, &vp);
	if (error == PUFFS_NOSUCHCOOKIE) {
		error = puffs_getvnode(dvp->v_mount,
		    lookup_msg->pvnr_newnode, lookup_msg->pvnr_vtype,
		    lookup_msg->pvnr_size, lookup_msg->pvnr_rdev, LK_EXCLUSIVE, &vp);
		if (error) {
			puffs_unlockvnode(dpn, &dltype);
			puffs_abortbutton(pmp, PUFFS_ABORT_LOOKUP, VPTOPNC(dvp),
			    lookup_msg->pvnr_newnode, ap->a_cnp);
			puffs_lockvnode(dpn, dltype);
			goto out;
		}
	} else if (error) {
		puffs_unlockvnode(dpn, &dltype);
		puffs_abortbutton(pmp, PUFFS_ABORT_LOOKUP, VPTOPNC(dvp),
		    lookup_msg->pvnr_newnode, ap->a_cnp);
		puffs_lockvnode(dpn, dltype);
		goto out;
	}

	*ap->a_vpp = vp;

	if ((cnp->cn_flags & MAKEENTRY) != 0 && PUFFS_USE_NAMECACHE(pmp))
		cache_enter(dvp, vp, cnp);

	if (lookup_msg->pvnr_cn.pkcn_consume)
		cnp->cn_consume = MIN(lookup_msg->pvnr_cn.pkcn_consume,
		    strlen(cnp->cn_nameptr) - cnp->cn_namelen);

 out:
	PUFFS_MSG_RELEASE(lookup);
	return error;
}

static int
puffs_vnop_create(struct vop_create_args *ap)
{
	PUFFS_MSG_VARS(vn, create);
	struct vnode *dvp = ap->a_dvp;
	struct puffs_node *dpn = VPTOPP(dvp);
	struct componentname *cnp = ap->a_cnp;
	struct mount *mp = dvp->v_mount;
	struct puffs_mount *pmp = MPTOPUFFSMP(mp);
	int dltype;
	int error;

	DPRINTF(("puffs_create: dvp %p, cnp: %s\n",
	    dvp, ap->a_cnp->cn_nameptr));

	PUFFS_MSG_ALLOC(vn, create);
	puffs_makecn(&create_msg->pvnr_cn, &create_msg->pvnr_cn_cred,
	    cnp, PUFFS_USE_FULLPNBUF(pmp));
	create_msg->pvnr_va = *ap->a_vap;
	puffs_msg_setinfo(park_create, PUFFSOP_VN,
	    PUFFS_VN_CREATE, VPTOPNC(dvp));

	/*
	 * Do the dance:
	 * + insert into queue ("interlock")
	 * + unlock vnode
	 * + wait for response
	 */
	puffs_msg_enqueue(pmp, park_create);
	puffs_unlockvnode(dpn, &dltype);
	error = puffs_msg_wait2(pmp, park_create, dpn, NULL);
	error = checkerr(pmp, error, __func__);
	PUFFS_LOCKVNODE(dpn, dltype, error);

	if (error)
		goto out;

	error = puffs_newnode(mp, dvp, ap->a_vpp,
	    create_msg->pvnr_newnode, cnp, ap->a_vap->va_type, 0);
	if (error) {
		puffs_unlockvnode(dpn, &dltype);
		puffs_abortbutton(pmp, PUFFS_ABORT_CREATE, dpn->pn_cookie,
		    create_msg->pvnr_newnode, cnp);
		puffs_lockvnode(dpn, dltype);
	}

 out:
	PUFFS_MSG_RELEASE(create);
	return error;
}

static int
puffs_vnop_mknod(struct vop_mknod_args *ap)
{
	PUFFS_MSG_VARS(vn, mknod);
	struct vnode *dvp = ap->a_dvp;
	struct puffs_node *dpn = VPTOPP(dvp);
	struct componentname *cnp = ap->a_cnp;
	struct mount *mp = dvp->v_mount;
	struct puffs_mount *pmp = MPTOPUFFSMP(mp);
	int dltype;
	int error;

	PUFFS_MSG_ALLOC(vn, mknod);
	puffs_makecn(&mknod_msg->pvnr_cn, &mknod_msg->pvnr_cn_cred,
	    cnp, PUFFS_USE_FULLPNBUF(pmp));
	mknod_msg->pvnr_va = *ap->a_vap;
	puffs_msg_setinfo(park_mknod, PUFFSOP_VN,
	    PUFFS_VN_MKNOD, VPTOPNC(dvp));

	puffs_msg_enqueue(pmp, park_mknod);
	puffs_unlockvnode(dpn, &dltype);
	error = puffs_msg_wait2(pmp, park_mknod, dpn, NULL);
	error = checkerr(pmp, error, __func__);
	PUFFS_LOCKVNODE(dpn, dltype, error);

	if (error)
		goto out;

	error = puffs_newnode(mp, dvp, ap->a_vpp,
	    mknod_msg->pvnr_newnode, cnp, ap->a_vap->va_type,
	    ap->a_vap->va_rdev);
	if (error) {
		puffs_unlockvnode(dpn, &dltype);
		puffs_abortbutton(pmp, PUFFS_ABORT_MKNOD, dpn->pn_cookie,
		    mknod_msg->pvnr_newnode, cnp);
		puffs_lockvnode(dpn, dltype);
	}

 out:
	PUFFS_MSG_RELEASE(mknod);
	return error;
}

static int
puffs_vnop_open(struct vop_open_args *ap)
{
	PUFFS_MSG_VARS(vn, open);
	struct vnode *vp = ap->a_vp;
	struct puffs_node *pn = VPTOPP(vp);
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	struct vattr va;
	int mode = ap->a_mode;
	int ltype;
	int error = 0;

	DPRINTF(("puffs_open: vp %p, mode 0x%x\n", vp, mode));

	if (vp->v_type == VREG && mode & FWRITE && !EXISTSOP(pmp, WRITE))
		return EROFS;

	if (!EXISTSOP(pmp, OPEN))
		goto out;

	PUFFS_MSG_ALLOC(vn, open);
	open_msg->pvnr_mode = mode;
	puffs_credcvt(&open_msg->pvnr_cred, ap->a_cred);
	puffs_msg_setinfo(park_open, PUFFSOP_VN,
	    PUFFS_VN_OPEN, VPTOPNC(vp));

	puffs_msg_enqueue(pmp, park_open);
	puffs_unlockvnode(pn, &ltype);
	error = puffs_msg_wait2(pmp, park_open, pn, NULL);
	error = checkerr(pmp, error, __func__);

	PUFFS_MSG_RELEASE(open);
	PUFFS_LOCKVNODE(pn, ltype, error);

out:
	if (!error) {
		error = VOP_GETATTR(vp, &va, ap->a_cred);
		if (error == 0) {
			DPRINTF(("puffs_vnop_open: create vobject: vp=%p\n",
			    vp));
			/* calls VOP_GETATTR */
			vnode_create_vobject(vp, va.va_size, ap->a_td);
		}
	}
	return error;
}

static int
puffs_vnop_close(struct vop_close_args *ap)
{
	PUFFS_MSG_VARS(vn, close);
	struct vnode *vp = ap->a_vp;
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);

	PUFFS_MSG_ALLOC(vn, close);
	puffs_msg_setfaf(park_close);
	close_msg->pvnr_fflag = ap->a_fflag;
	puffs_credcvt(&close_msg->pvnr_cred, ap->a_cred);
	puffs_msg_setinfo(park_close, PUFFSOP_VN,
	    PUFFS_VN_CLOSE, VPTOPNC(vp));

	puffs_msg_enqueue(pmp, park_close);
	PUFFS_MSG_RELEASE(close);
	return 0;
}

static int
puffs_vnop_access(struct vop_access_args *ap)
{
	PUFFS_MSG_VARS(vn, access);
	struct vnode *vp = ap->a_vp;
	struct puffs_node *pn = VPTOPP(vp);
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	accmode_t accmode = ap->a_accmode;
	int ltype;
	int error;

	if (accmode & VWRITE) {
		switch (vp->v_type) {
		case VDIR:
		case VLNK:
		case VREG:
			if ((vp->v_mount->mnt_flag & MNT_RDONLY)
			    || !EXISTSOP(pmp, WRITE))
				return EROFS;
			break;
		default:
			break;
		}
	}

	if (!EXISTSOP(pmp, ACCESS))
		return 0;

	PUFFS_MSG_ALLOC(vn, access);
	access_msg->pvnr_mode = ap->a_accmode;
	puffs_credcvt(&access_msg->pvnr_cred, ap->a_cred);
	puffs_msg_setinfo(park_access, PUFFSOP_VN,
	    PUFFS_VN_ACCESS, VPTOPNC(vp));

	puffs_msg_enqueue(pmp, park_access);
	puffs_unlockvnode(pn, &ltype);
	error = puffs_msg_wait2(pmp, park_access, pn, NULL);
	error = checkerr(pmp, error, __func__);
	PUFFS_MSG_RELEASE(access);
	PUFFS_LOCKVNODE(pn, ltype, error);

	return error;
}

static int
puffs_vnop_getattr(struct vop_getattr_args *ap)
{
	PUFFS_MSG_VARS(vn, getattr);
	struct vnode *vp = ap->a_vp;
	struct mount *mp = vp->v_mount;
	struct puffs_node *pn = VPTOPP(vp);
	struct puffs_mount *pmp = MPTOPUFFSMP(mp);
	struct vattr *vap, *rvap;
	int ltype;
	int error = 0;

	vap = ap->a_vap;

	PUFFS_MSG_ALLOC(vn, getattr);
	vattr_null(&getattr_msg->pvnr_va);
	puffs_credcvt(&getattr_msg->pvnr_cred, ap->a_cred);
	puffs_msg_setinfo(park_getattr, PUFFSOP_VN,
	    PUFFS_VN_GETATTR, VPTOPNC(vp));

	puffs_msg_enqueue(pmp, park_getattr);
	puffs_unlockvnode(pn, &ltype);
	error = puffs_msg_wait2(pmp, park_getattr, pn, NULL);
	error = checkerr(pmp, error, __func__);
	PUFFS_LOCKVNODE(pn, ltype, error);
	if (error)
		goto out;

	rvap = &getattr_msg->pvnr_va;

	/*
	 * Don't listen to the file server regarding special device
	 * size info, the file server doesn't know anything about them.
	 */
	if (vp->v_type == VBLK || vp->v_type == VCHR) {
		rvap->va_size = 0;
		rvap->va_blocksize = DEV_BSIZE;
	}

	(void) memcpy(vap, rvap, sizeof(struct vattr));
	vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];

	if (pn->pn_stat & PNODE_METACACHE_ATIME)
		vap->va_atime = pn->pn_mc_atime;
	if (pn->pn_stat & PNODE_METACACHE_CTIME)
		vap->va_ctime = pn->pn_mc_ctime;
	if (pn->pn_stat & PNODE_METACACHE_MTIME)
		vap->va_mtime = pn->pn_mc_mtime;
	if (pn->pn_stat & PNODE_METACACHE_SIZE) {
		vap->va_size = pn->pn_mc_size;
	} else {
		if (rvap->va_size != VNOVAL
		    && vp->v_type != VBLK && vp->v_type != VCHR) {
			vnode_pager_setsize(vp, rvap->va_size);
			pn->pn_serversize = rvap->va_size;
		}
	}

 out:
	PUFFS_MSG_RELEASE(getattr);
	return error;
}

static int
dosetattr(struct vnode *vp, struct vattr *vap, struct ucred *cred, int chsize)
{
	PUFFS_MSG_VARS(vn, setattr);
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	struct puffs_node *pn = vp->v_data;
	int ltype;
	int error;

	if ((vp->v_mount->mnt_flag & MNT_RDONLY) &&
	    (vap->va_uid != (uid_t)VNOVAL || vap->va_gid != (gid_t)VNOVAL
	    || vap->va_atime.tv_sec != VNOVAL || vap->va_mtime.tv_sec != VNOVAL
	    || vap->va_mode != (mode_t)VNOVAL))
		return EROFS;

	if ((vp->v_mount->mnt_flag & MNT_RDONLY)
	    && vp->v_type == VREG && vap->va_size != VNOVAL)
		return EROFS;

	/*
	 * Flush metacache first.  If we are called with some explicit
	 * parameters, treat them as information overriding metacache
	 * information.
	 */
	if (pn->pn_stat & PNODE_METACACHE_MASK) {
		if ((pn->pn_stat & PNODE_METACACHE_ATIME)
		    && vap->va_atime.tv_sec == VNOVAL)
			vap->va_atime = pn->pn_mc_atime;
		if ((pn->pn_stat & PNODE_METACACHE_CTIME)
		    && vap->va_ctime.tv_sec == VNOVAL)
			vap->va_ctime = pn->pn_mc_ctime;
		if ((pn->pn_stat & PNODE_METACACHE_MTIME)
		    && vap->va_mtime.tv_sec == VNOVAL)
			vap->va_mtime = pn->pn_mc_mtime;
		if ((pn->pn_stat & PNODE_METACACHE_SIZE)
		    && vap->va_size == VNOVAL)
			vap->va_size = pn->pn_mc_size;

		pn->pn_stat &= ~PNODE_METACACHE_MASK;
	}

	PUFFS_MSG_ALLOC(vn, setattr);
	(void)memcpy(&setattr_msg->pvnr_va, vap, sizeof(struct vattr));
	puffs_credcvt(&setattr_msg->pvnr_cred, cred);
	puffs_msg_setinfo(park_setattr, PUFFSOP_VN,
	    PUFFS_VN_SETATTR, VPTOPNC(vp));

	puffs_msg_enqueue(pmp, park_setattr);
	puffs_unlockvnode(pn, &ltype);
	error = puffs_msg_wait2(pmp, park_setattr, pn, NULL);
	PUFFS_MSG_RELEASE(setattr);
	PUFFS_LOCKVNODE(pn, ltype, error);
	error = checkerr(pmp, error, __func__);
	if (error)
		return error;

	if (vap->va_size != VNOVAL) {
		pn->pn_serversize = vap->va_size;
		if (chsize)
			vnode_pager_setsize(vp, vap->va_size);
	}

	return 0;
}

static int
puffs_vnop_setattr(struct vop_setattr_args *ap)
{
	return dosetattr(ap->a_vp, ap->a_vap, ap->a_cred, 1);
}

static __inline int
doinact(struct puffs_mount *pmp, int iaflag)
{

	if (EXISTSOP(pmp, INACTIVE))
		if (pmp->pmp_flags & PUFFS_KFLAG_IAONDEMAND)
			if (iaflag || ALLOPS(pmp))
				return 1;
			else
				return 0;
		else
			return 1;
	else
		return 0;
}

static void
callinactive(struct puffs_mount *pmp, puffs_cookie_t ck, int iaflag)
{
	int error;
	PUFFS_MSG_VARS(vn, inactive);

	if (doinact(pmp, iaflag)) {
		PUFFS_MSG_ALLOC(vn, inactive);
		puffs_msg_setinfo(park_inactive, PUFFSOP_VN,
		    PUFFS_VN_INACTIVE, ck);

		PUFFS_MSG_ENQUEUEWAIT(pmp, park_inactive, error);
		PUFFS_MSG_RELEASE(inactive);
	}
}

/* XXX: callinactive can't setback */
int
static puffs_vnop_inactive(struct vop_inactive_args *ap)
{
	PUFFS_MSG_VARS(vn, inactive);
	struct vnode *vp = ap->a_vp;
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	struct puffs_node *pnode;

	pnode = vp->v_data;

	if (doinact(pmp, pnode->pn_stat & PNODE_DOINACT)) {
		/*
		 * do not wait for reply from userspace, otherwise it may
		 * deadlock.
		 */
		PUFFS_MSG_ALLOC(vn, inactive);
		puffs_msg_setfaf(park_inactive);
		puffs_msg_setinfo(park_inactive, PUFFSOP_VN,
		    PUFFS_VN_INACTIVE, VPTOPNC(vp));

		puffs_msg_enqueue(pmp, park_inactive);
		PUFFS_MSG_RELEASE(inactive);
	}
	pnode->pn_stat &= ~PNODE_DOINACT;

	/*
	 * file server thinks it's gone?  then don't be afraid care,
	 * node's life was already all it would ever be
	 */
	if ((pnode->pn_stat & PNODE_NOREFS) != 0)
		vrecycle(vp, ap->a_td);

	return 0;
}

static void
callreclaim(struct puffs_mount *pmp, puffs_cookie_t ck)
{
	PUFFS_MSG_VARS(vn, reclaim);

	if (!EXISTSOP(pmp, RECLAIM))
		return;

	PUFFS_MSG_ALLOC(vn, reclaim);
	puffs_msg_setfaf(park_reclaim);
	puffs_msg_setinfo(park_reclaim, PUFFSOP_VN, PUFFS_VN_RECLAIM, ck);

	puffs_msg_enqueue(pmp, park_reclaim);
	PUFFS_MSG_RELEASE(reclaim);
}

/*
 * always FAF, we don't really care if the server wants to fail to
 * reclaim the node or not
 */
static int
puffs_vnop_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);

	/*
	 * first things first: check if someone is trying to reclaim the
	 * root vnode.  do not allow that to travel to userspace.
	 * Note that we don't need to take the lock similarly to
	 * puffs_root(), since there is only one of us.
	 */
	if (vp->v_vflag & VV_ROOT) {
		mtx_lock(&pmp->pmp_lock);
		KASSERT(pmp->pmp_root != NULL, ("pmp->pmp_root != NULL"));
		pmp->pmp_root = NULL;
		mtx_unlock(&pmp->pmp_lock);
		goto out;
	}

	callreclaim(MPTOPUFFSMP(vp->v_mount), VPTOPNC(vp));

 out:
	if (PUFFS_USE_NAMECACHE(pmp))
		cache_purge(vp);
	puffs_putvnode(vp);

	return 0;
}

#define CSIZE sizeof(**ap->a_cookies)
static int
puffs_vnop_readdir(struct vop_readdir_args *ap)
{
	PUFFS_MSG_VARS(vn, readdir);
	struct vnode *vp = ap->a_vp;
	struct puffs_node *pn = VPTOPP(vp);
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	size_t argsize, tomove, cookiemem, cookiesmax;
	struct uio *uio = ap->a_uio;
	size_t howmuch, resid;
	int ltype;
	int error;

	const static struct dirent _dirent_minsize = {
		.d_namlen = 0,
	};

	/*
	 * ok, so we need: resid + cookiemem = maxreq
	 * => resid + cookiesize * (resid/minsize) = maxreq
	 * => resid + cookiesize/minsize * resid = maxreq
	 * => (cookiesize/minsize + 1) * resid = maxreq
	 * => resid = maxreq / (cookiesize/minsize + 1)
	 *
	 * Since cookiesize <= minsize and we're not very big on floats,
	 * we approximate that to be 1.  Therefore:
	 *
	 * resid = maxreq / 2;
	 *
	 * Well, at least we didn't have to use differential equations
	 * or the Gram-Schmidt process.
	 *
	 * (yes, I'm very afraid of this)
	 */
	KASSERT(CSIZE <= GENERIC_DIRSIZ(&_dirent_minsize), ("CSIZE <= _DIRENT_MINSIZE"));

	if (ap->a_cookies) {
		KASSERT(ap->a_ncookies != NULL, ("a_ncookies != NULL"));
		if (pmp->pmp_args.pa_fhsize == 0)
			return EOPNOTSUPP;
		resid = PUFFS_TOMOVE(uio->uio_resid, pmp) / 2;
		cookiesmax = resid/GENERIC_DIRSIZ(&_dirent_minsize);
		cookiemem = ALIGN(cookiesmax*CSIZE); /* play safe */
	} else {
		resid = PUFFS_TOMOVE(uio->uio_resid, pmp);
		cookiesmax = 0;
		cookiemem = 0;
	}

	argsize = sizeof(struct puffs_vnmsg_readdir);
	tomove = resid + cookiemem;
	puffs_msgmem_alloc(argsize + tomove, &park_readdir,
	    (void *)&readdir_msg, 1);

	puffs_credcvt(&readdir_msg->pvnr_cred, ap->a_cred);
	readdir_msg->pvnr_offset = uio->uio_offset;
	readdir_msg->pvnr_resid = resid;
	readdir_msg->pvnr_ncookies = cookiesmax;
	readdir_msg->pvnr_eofflag = 0;
	readdir_msg->pvnr_dentoff = cookiemem;
	puffs_msg_setinfo(park_readdir, PUFFSOP_VN,
	    PUFFS_VN_READDIR, VPTOPNC(vp));
	puffs_msg_setdelta(park_readdir, tomove);

	puffs_msg_enqueue(pmp, park_readdir);
	puffs_unlockvnode(pn, &ltype);
	error = puffs_msg_wait2(pmp, park_readdir, pn, NULL);
	error = checkerr(pmp, error, __func__);
	PUFFS_LOCKVNODE(pn, ltype, error);
	if (error)
		goto out;

	/* userspace is cheating? */
	if (readdir_msg->pvnr_resid > resid) {
		puffs_senderr(pmp, PUFFS_ERR_READDIR, E2BIG,
		    "resid grew", VPTOPNC(vp));
		ERROUT(EPROTO);
	}
	if (readdir_msg->pvnr_ncookies > cookiesmax) {
		puffs_senderr(pmp, PUFFS_ERR_READDIR, E2BIG,
		    "too many cookies", VPTOPNC(vp));
		ERROUT(EPROTO);
	}

	/* check eof */
	if (readdir_msg->pvnr_eofflag)
		*ap->a_eofflag = 1;

	/* bouncy-wouncy with the directory data */
	howmuch = resid - readdir_msg->pvnr_resid;

	/* force eof if no data was returned (getcwd() needs this) */
	if (howmuch == 0) {
		*ap->a_eofflag = 1;
		goto out;
	}

	error = uiomove(readdir_msg->pvnr_data + cookiemem, howmuch, uio);
	if (error)
		goto out;

	/* provide cookies to caller if so desired */
	if (ap->a_cookies) {
		*ap->a_cookies = malloc(readdir_msg->pvnr_ncookies*CSIZE,
		    M_TEMP, M_WAITOK);
		*ap->a_ncookies = readdir_msg->pvnr_ncookies;
		memcpy(*ap->a_cookies, readdir_msg->pvnr_data,
		    *ap->a_ncookies*CSIZE);
	}

	/* next readdir starts here */
	uio->uio_offset = readdir_msg->pvnr_offset;

 out:
	puffs_msgmem_release(park_readdir);
	return error;
}
#undef CSIZE

static int
puffs_vnop_fsync(struct vop_fsync_args *ap)
{
	PUFFS_MSG_VARS(vn, fsync);
	struct vnode *vp = ap->a_vp;
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	struct puffs_node *pn;
	struct vattr va;
	int ltype;
	int error, dofaf;

	pn = VPTOPP(vp);

	/* flush out information from our metacache, see vop_setattr */
	if (pn->pn_stat & PNODE_METACACHE_MASK) {
		vattr_null(&va);
		error = VOP_SETATTR(vp, &va, FSCRED);
		if (error)
			return error;
	}

	/*
	 * flush pages to avoid being overly dirty
	 */

	vop_stdfsync(ap);

	/*
	 * HELLO!  We exit already here if the user server does not
	 * support fsync OR if we should call fsync for a node which
	 * has references neither in the kernel or the fs server.
	 * Otherwise we continue to issue fsync() forward.
	 */
	if (!EXISTSOP(pmp, FSYNC))
		return 0;

	dofaf = (ap->a_waitfor & MNT_WAIT) == 0 || ap->a_waitfor == MNT_LAZY;

	PUFFS_MSG_ALLOC(vn, fsync);
	if (dofaf)
		puffs_msg_setfaf(park_fsync);

	puffs_credcvt(&fsync_msg->pvnr_cred, ap->a_td->td_ucred);
	fsync_msg->pvnr_flags = ap->a_waitfor;
	fsync_msg->pvnr_offlo = 0;
	fsync_msg->pvnr_offhi = 0; /* XXX_TS userland should handle it */
	puffs_msg_setinfo(park_fsync, PUFFSOP_VN,
	    PUFFS_VN_FSYNC, VPTOPNC(vp));

	puffs_msg_enqueue(pmp, park_fsync);
	if (!dofaf) {
		puffs_unlockvnode(pn, &ltype);
		error = puffs_msg_wait2(pmp, park_fsync, pn, NULL);
		error = checkerr(pmp, error, __func__);
		PUFFS_LOCKVNODE(pn, ltype, error);
	} else {
		error = 0;
	}
	PUFFS_MSG_RELEASE(fsync);

	return error;
}

static int
callremove(struct puffs_mount *pmp, puffs_cookie_t dck, puffs_cookie_t ck,
	struct componentname *cnp)
{
	PUFFS_MSG_VARS(vn, remove);
	int error;

	PUFFS_MSG_ALLOC(vn, remove);
	remove_msg->pvnr_cookie_targ = ck;
	puffs_makecn(&remove_msg->pvnr_cn, &remove_msg->pvnr_cn_cred,
	    cnp, PUFFS_USE_FULLPNBUF(pmp));
	puffs_msg_setinfo(park_remove, PUFFSOP_VN, PUFFS_VN_REMOVE, dck);

	PUFFS_MSG_ENQUEUEWAIT(pmp, park_remove, error);
	PUFFS_MSG_RELEASE(remove);

	return checkerr(pmp, error, __func__);
}

/*
 * XXX: can't use callremove now because can't catch setbacks with
 * it due to lack of a pnode argument.
 */
static int
puffs_vnop_remove(struct vop_remove_args *ap)
{
	PUFFS_MSG_VARS(vn, remove);
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;
	struct puffs_node *dpn = VPTOPP(dvp);
	struct puffs_node *pn = VPTOPP(vp);
	struct componentname *cnp = ap->a_cnp;
	struct mount *mp = dvp->v_mount;
	struct puffs_mount *pmp = MPTOPUFFSMP(mp);
	int error;
	int ltype, dltype;

	PUFFS_MSG_ALLOC(vn, remove);
	remove_msg->pvnr_cookie_targ = VPTOPNC(vp);
	puffs_makecn(&remove_msg->pvnr_cn, &remove_msg->pvnr_cn_cred,
	    cnp, PUFFS_USE_FULLPNBUF(pmp));
	puffs_msg_setinfo(park_remove, PUFFSOP_VN,
	    PUFFS_VN_REMOVE, VPTOPNC(dvp));

	puffs_msg_enqueue(pmp, park_remove);
	puffs_unlockvnode(dpn, &dltype);
	if (dvp == vp) {
		mtx_lock(&pn->pn_mtx);
		puffs_referencenode(pn);
		mtx_unlock(&pn->pn_mtx);
	} else
		puffs_unlockvnode(pn, &ltype);
	error = puffs_msg_wait2(pmp, park_remove, dpn, pn);

	PUFFS_MSG_RELEASE(remove);

	if (dvp == vp)
		puffs_releasenode(pn);
	else
		PUFFS_LOCKVNODE(dpn, dltype, error);
	PUFFS_LOCKVNODE(pn, dltype, error);

	error = checkerr(pmp, error, __func__);
	return error;
}

static int
puffs_vnop_mkdir(struct vop_mkdir_args *ap)
{
	PUFFS_MSG_VARS(vn, mkdir);
	struct vnode *dvp = ap->a_dvp;
	struct puffs_node *dpn = VPTOPP(dvp);
	struct componentname *cnp = ap->a_cnp;
	struct mount *mp = dvp->v_mount;
	struct puffs_mount *pmp = MPTOPUFFSMP(mp);
	int dltype;
	int error;

	PUFFS_MSG_ALLOC(vn, mkdir);
	puffs_makecn(&mkdir_msg->pvnr_cn, &mkdir_msg->pvnr_cn_cred,
	    cnp, PUFFS_USE_FULLPNBUF(pmp));
	mkdir_msg->pvnr_va = *ap->a_vap;
	puffs_msg_setinfo(park_mkdir, PUFFSOP_VN,
	    PUFFS_VN_MKDIR, VPTOPNC(dvp));

	puffs_msg_enqueue(pmp, park_mkdir);
	puffs_unlockvnode(dpn, &dltype);
	error = puffs_msg_wait2(pmp, park_mkdir, dpn, NULL);

	error = checkerr(pmp, error, __func__);
	PUFFS_LOCKVNODE(dpn, dltype, error);
	if (error)
		goto out;

	error = puffs_newnode(mp, dvp, ap->a_vpp,
	    mkdir_msg->pvnr_newnode, cnp, VDIR, 0);
	if (error) {
		puffs_unlockvnode(dpn, &dltype);
		puffs_abortbutton(pmp, PUFFS_ABORT_MKDIR, dpn->pn_cookie,
		    mkdir_msg->pvnr_newnode, cnp);
		puffs_lockvnode(dpn, dltype);
	}

 out:
	PUFFS_MSG_RELEASE(mkdir);
	return error;
}

static int
callrmdir(struct puffs_mount *pmp, puffs_cookie_t dck, puffs_cookie_t ck,
	struct componentname *cnp)
{
	PUFFS_MSG_VARS(vn, rmdir);
	int error;

	PUFFS_MSG_ALLOC(vn, rmdir);
	rmdir_msg->pvnr_cookie_targ = ck;
	puffs_makecn(&rmdir_msg->pvnr_cn, &rmdir_msg->pvnr_cn_cred,
	    cnp, PUFFS_USE_FULLPNBUF(pmp));
	puffs_msg_setinfo(park_rmdir, PUFFSOP_VN, PUFFS_VN_RMDIR, dck);

	PUFFS_MSG_ENQUEUEWAIT(pmp, park_rmdir, error);
	PUFFS_MSG_RELEASE(rmdir);

	return checkerr(pmp, error, __func__);
}

static int
puffs_vnop_rmdir(struct vop_rmdir_args *ap)
{
	PUFFS_MSG_VARS(vn, rmdir);
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;
	struct puffs_node *dpn = VPTOPP(dvp);
	struct puffs_node *pn = VPTOPP(vp);
	struct puffs_mount *pmp = MPTOPUFFSMP(dvp->v_mount);
	struct componentname *cnp = ap->a_cnp;
	int dltype, ltype;
	int error;

	PUFFS_MSG_ALLOC(vn, rmdir);
	rmdir_msg->pvnr_cookie_targ = VPTOPNC(vp);
	puffs_makecn(&rmdir_msg->pvnr_cn, &rmdir_msg->pvnr_cn_cred,
	    cnp, PUFFS_USE_FULLPNBUF(pmp));
	puffs_msg_setinfo(park_rmdir, PUFFSOP_VN,
	    PUFFS_VN_RMDIR, VPTOPNC(dvp));

	puffs_msg_enqueue(pmp, park_rmdir);
	puffs_unlockvnode(dpn, &dltype);
	puffs_unlockvnode(pn, &ltype);
	error = puffs_msg_wait2(pmp, park_rmdir, dpn, pn);

	PUFFS_MSG_RELEASE(rmdir);

	/* XXX: some call cache_purge() *for both vnodes* here, investigate */
	PUFFS_LOCKVNODE(dpn, dltype, error);
	PUFFS_LOCKVNODE(pn, ltype, error);

	return error;
}

static int
puffs_vnop_link(struct vop_link_args *ap)
{
	PUFFS_MSG_VARS(vn, link);
	struct vnode *dvp = ap->a_tdvp;
	struct vnode *vp = ap->a_vp;
	struct puffs_node *dpn = VPTOPP(dvp);
	struct puffs_node *pn = VPTOPP(vp);
	struct puffs_mount *pmp = MPTOPUFFSMP(dvp->v_mount);
	struct componentname *cnp = ap->a_cnp;
	int dltype;
	int error;

	PUFFS_MSG_ALLOC(vn, link);
	link_msg->pvnr_cookie_targ = VPTOPNC(vp);
	puffs_makecn(&link_msg->pvnr_cn, &link_msg->pvnr_cn_cred,
	    cnp, PUFFS_USE_FULLPNBUF(pmp));
	puffs_msg_setinfo(park_link, PUFFSOP_VN,
	    PUFFS_VN_LINK, VPTOPNC(dvp));

	puffs_msg_enqueue(pmp, park_link);
	puffs_unlockvnode(dpn, &dltype);
	mtx_lock(&pn->pn_mtx);
	puffs_referencenode(pn);
	mtx_unlock(&pn->pn_mtx);
	error = puffs_msg_wait2(pmp, park_link, dpn, pn);

	PUFFS_MSG_RELEASE(link);

	error = checkerr(pmp, error, __func__);
	PUFFS_LOCKVNODE(dpn, dltype, error);

	/*
	 * XXX: stay in touch with the cache.  I don't like this, but
	 * don't have a better solution either.  See also puffs_rename().
	 */
	if (error == 0)
		puffs_updatenode(pn, PUFFS_UPDATECTIME, 0);

	puffs_releasenode(pn);

	return error;
}

static int
puffs_vnop_symlink(struct vop_symlink_args *ap)
{
	PUFFS_MSG_VARS(vn, symlink);
	struct vnode *dvp = ap->a_dvp;
	struct puffs_node *dpn = VPTOPP(dvp);
	struct mount *mp = dvp->v_mount;
	struct puffs_mount *pmp = MPTOPUFFSMP(dvp->v_mount);
	struct componentname *cnp = ap->a_cnp;
	int dltype;
	int error;

	*ap->a_vpp = NULL;

	PUFFS_MSG_ALLOC(vn, symlink);
	puffs_makecn(&symlink_msg->pvnr_cn, &symlink_msg->pvnr_cn_cred,
		cnp, PUFFS_USE_FULLPNBUF(pmp));
	symlink_msg->pvnr_va = *ap->a_vap;
	(void)strlcpy(symlink_msg->pvnr_link, ap->a_target,
	    sizeof(symlink_msg->pvnr_link));
	puffs_msg_setinfo(park_symlink, PUFFSOP_VN,
	    PUFFS_VN_SYMLINK, VPTOPNC(dvp));

	puffs_msg_enqueue(pmp, park_symlink);
	puffs_unlockvnode(dpn, &dltype);
	error = puffs_msg_wait2(pmp, park_symlink, dpn, NULL);

	error = checkerr(pmp, error, __func__);
	PUFFS_LOCKVNODE(dpn, dltype, error);
	if (error)
		goto out;

	error = puffs_newnode(mp, dvp, ap->a_vpp,
	    symlink_msg->pvnr_newnode, cnp, VLNK, 0);
	if (error) {
		puffs_unlockvnode(dpn, &dltype);
		puffs_abortbutton(pmp, PUFFS_ABORT_SYMLINK, dpn->pn_cookie,
		    symlink_msg->pvnr_newnode, cnp);
		puffs_lockvnode(dpn, dltype);
	}

 out:
	PUFFS_MSG_RELEASE(symlink);

	return error;
}

static int
puffs_vnop_readlink(struct vop_readlink_args *ap)
{
	PUFFS_MSG_VARS(vn, readlink);
	struct vnode *vp = ap->a_vp;
	struct puffs_mount *pmp = MPTOPUFFSMP(ap->a_vp->v_mount);
	struct puffs_node *pn = VPTOPP(vp);
	size_t linklen;
	int ltype;
	int error;

	PUFFS_MSG_ALLOC(vn, readlink);
	puffs_credcvt(&readlink_msg->pvnr_cred, ap->a_cred);
	linklen = sizeof(readlink_msg->pvnr_link);
	readlink_msg->pvnr_linklen = linklen;
	puffs_msg_setinfo(park_readlink, PUFFSOP_VN,
	    PUFFS_VN_READLINK, VPTOPNC(vp));

	puffs_msg_enqueue(pmp, park_readlink);
	puffs_unlockvnode(pn, &ltype);
	error = puffs_msg_wait2(pmp, park_readlink, pn, NULL);
	error = checkerr(pmp, error, __func__);
	PUFFS_LOCKVNODE(pn, ltype, error);
	if (error)
		goto out;

	/* bad bad user file server */
	if (readlink_msg->pvnr_linklen > linklen) {
		puffs_senderr(pmp, PUFFS_ERR_READLINK, E2BIG,
		    "linklen too big", VPTOPNC(ap->a_vp));
		error = EPROTO;
		goto out;
	}

	error = uiomove(&readlink_msg->pvnr_link, readlink_msg->pvnr_linklen,
	    ap->a_uio);
 out:
	PUFFS_MSG_RELEASE(readlink);
	return error;
}

static int
puffs_vnop_rename(struct vop_rename_args *ap)
{
	PUFFS_MSG_VARS(vn, rename);
	struct vnode *fdvp = ap->a_fdvp;
	struct puffs_node *fpn = ap->a_fvp->v_data;
	struct puffs_node *tdpn = VPTOPP(ap->a_tdvp);
	struct puffs_node *tpn = NULL;
	struct puffs_mount *pmp = MPTOPUFFSMP(fdvp->v_mount);
	int tltype, tdltype;
	int error;

	if (ap->a_fvp->v_mount != ap->a_tdvp->v_mount)
		ERROUT(EXDEV);

	PUFFS_MSG_ALLOC(vn, rename);
	rename_msg->pvnr_cookie_src = VPTOPNC(ap->a_fvp);
	rename_msg->pvnr_cookie_targdir = VPTOPNC(ap->a_tdvp);
	if (ap->a_tvp)
		rename_msg->pvnr_cookie_targ = VPTOPNC(ap->a_tvp);
	else
		rename_msg->pvnr_cookie_targ = NULL;
	puffs_makecn(&rename_msg->pvnr_cn_src, &rename_msg->pvnr_cn_src_cred,
	    ap->a_fcnp, PUFFS_USE_FULLPNBUF(pmp));
	puffs_makecn(&rename_msg->pvnr_cn_targ, &rename_msg->pvnr_cn_targ_cred,
	    ap->a_tcnp, PUFFS_USE_FULLPNBUF(pmp));
	puffs_msg_setinfo(park_rename, PUFFSOP_VN,
	    PUFFS_VN_RENAME, VPTOPNC(fdvp));

	puffs_msg_enqueue(pmp, park_rename);
	if (ap->a_tvp) {
		tpn = VPTOPP(ap->a_tvp);
		puffs_unlockvnode(tpn, &tltype);
	}
	puffs_unlockvnode(tdpn, &tdltype);
	error = puffs_msg_wait2(pmp, park_rename, fdvp->v_data, NULL);
	error = checkerr(pmp, error, __func__);
	if (ap->a_tvp) {
		PUFFS_LOCKVNODE(tpn, tltype, error);
	}
	PUFFS_LOCKVNODE(tdpn, tdltype, error);
	if (error)
		goto out;

	/*
	 * XXX: stay in touch with the cache.  I don't like this, but
	 * don't have a better solution either.  See also puffs_link().
	 */
	if (error == 0)
		puffs_updatenode(fpn, PUFFS_UPDATECTIME, 0);

 out:
	PUFFS_MSG_RELEASE(rename);
	if (ap->a_tvp != NULL)
		vput(ap->a_tvp);
	if (ap->a_tdvp == ap->a_tvp)
		vrele(ap->a_tdvp);
	else
		vput(ap->a_tdvp);

	vrele(ap->a_fdvp);
	vrele(ap->a_fvp);

	return error;
}

#define RWARGS(cont, iofl, move, offset, creds)				\
	(cont)->pvnr_ioflag = (iofl);					\
	(cont)->pvnr_resid = (move);					\
	(cont)->pvnr_offset = (offset);					\
	puffs_credcvt(&(cont)->pvnr_cred, creds)

static inline int
puffs_ismapped(struct vnode *vp)
{
	vm_object_t object = vp->v_object;

	if (object == NULL)
		return (0);

	return (object->resident_page_count > 0 || object->cache != NULL);
}

static int
puffs_mappedread(struct vnode *vp, struct uio *uio)
{
	vm_page_t m;
	vm_offset_t moffset;
	ssize_t msize;
	int error = 0;

	moffset = uio->uio_offset & PAGE_MASK;
	msize = qmin(uio->uio_resid, PAGE_SIZE - moffset);

	ASSERT_VOP_LOCKED(vp, "puffs_mappedread");
	VM_OBJECT_LOCK(vp->v_object);
lookupvpg:
	m = vm_page_lookup(vp->v_object, OFF_TO_IDX(uio->uio_offset));
	if (m != NULL && vm_page_is_valid(m, moffset, msize)) {
		if (vm_page_sleep_if_busy(m, FALSE, "puffsmr"))
			goto lookupvpg;
		vm_page_busy(m);
		VM_OBJECT_UNLOCK(vp->v_object);
		DPRINTF(("puffs_mappedread: offset=0x%jx moffset=0x%jx msize=0x%jx\n",
		    uio->uio_offset, (intmax_t)moffset, (intmax_t)msize));
		error = uiomove_fromphys(&m, moffset, msize, uio);
		VM_OBJECT_LOCK(vp->v_object);
		vm_page_wakeup(m);
	} else if (m != NULL && uio->uio_segflg == UIO_NOCOPY) {
		/* FIXME: UIO_NOCOPY is not supported */
		error = EIO;
	}
	VM_OBJECT_UNLOCK(vp->v_object);

	return (error);
}

static int
puffs_mappedwrite(struct vnode *vp, struct uio *uio, char *pagedata)
{
	vm_page_t m;
	vm_pindex_t idx;
	vm_offset_t moffset;
	struct sf_buf *sf;
	ssize_t msize;
	char *ma;
	int error = 0;

	moffset = uio->uio_offset & PAGE_MASK;
	msize = qmin(PAGE_SIZE - moffset, uio->uio_resid);

	ASSERT_VOP_LOCKED(vp, "puffs_mappedwrite");
	VM_OBJECT_LOCK(vp->v_object);
lookupvpg:
	idx = OFF_TO_IDX(uio->uio_offset);
	m = vm_page_lookup(vp->v_object, idx);
	if (m != NULL && vm_page_is_valid(m, 0, moffset + msize)) {
		if (vm_page_sleep_if_busy(m, FALSE, "puffsmw"))
			goto lookupvpg;
		vm_page_busy(m);
		if (moffset == 0) {
			vm_page_lock_queues();
			vm_page_undirty(m);
			vm_page_unlock_queues();
		}
		VM_OBJECT_UNLOCK(vp->v_object);
		DPRINTF(("puffs_mappedwrite: offset=0x%jx moffset=0x%jx msize=0x%jx\n",
		    uio->uio_offset, (intmax_t)moffset, (intmax_t)msize));
		sched_pin();
		sf = sf_buf_alloc(m, SFB_CPUPRIVATE);
		ma = (char *)sf_buf_kva(sf);
		error = uiomove(ma + moffset, msize, uio);
		memcpy(pagedata, ma, msize);
		sf_buf_free(sf);
		sched_unpin();
		VM_OBJECT_LOCK(vp->v_object);
		vm_page_wakeup(m);
	} else if (__predict_false(vp->v_object->cache != NULL)) {
		DPRINTF(("puffs_mappedwrite: free cache: 0x%jx\n",
		    uio->uio_offset - moffset));
		vm_page_cache_free(vp->v_object, idx, idx + 1);
	}
	VM_OBJECT_UNLOCK(vp->v_object);

	return error;
}

static int
puffs_vnop_read(struct vop_read_args *ap)
{
	PUFFS_MSG_VARS(vn, read);
	struct vnode *vp = ap->a_vp;
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	struct puffs_node *pn = VPTOPP(vp);
	struct uio *uio = ap->a_uio;
	size_t tomove, argsize;
#ifdef XXX_TS
	size_t bytelen;
#endif
	int error;
	int ltype;
	int mapped, vplocked;

	read_msg = NULL;
	error = 0;

	/* std sanity */
	if (uio->uio_resid == 0)
		return 0;
	if (uio->uio_offset < 0)
		return EINVAL;

	if (0 && vp->v_type == VREG && PUFFS_USE_PAGECACHE(pmp)) {
		return EIO;
#ifdef XXX_TS
		const int advice = IO_ADV_DECODE(ap->a_ioflag);

		while (uio->uio_resid > 0) {
			bytelen = MIN(uio->uio_resid,
			    vp->v_size - uio->uio_offset);
			if (bytelen == 0)
				break;

			error = ubc_uiomove(&vp->v_uobj, uio, bytelen, advice,
			    UBC_READ | UBC_PARTIALOK | UBC_UNMAP_FLAG(vp));
			if (error)
				break;
		}

		if ((vp->v_mount->mnt_flag & MNT_NOATIME) == 0)
			puffs_updatenode(VPTOPP(vp), PUFFS_UPDATEATIME, 0);
#endif
	} else {
		mapped = puffs_ismapped(vp);
		vplocked = 1;
		if (!mapped) {
			puffs_unlockvnode(pn, &ltype);
			vplocked = 0;
		}

		/*
		 * in case it's not a regular file or we're operating
		 * uncached, do read in the old-fashioned style,
		 * i.e. explicit read operations
		 */

		tomove = PUFFS_TOMOVE(uio->uio_resid, pmp);
		argsize = sizeof(struct puffs_vnmsg_read);
		puffs_msgmem_alloc(argsize + tomove, &park_read,
		    (void *)&read_msg, 1);

		error = 0;
		while (uio->uio_resid > 0) {
			if (mapped) {
				tomove = uio->uio_resid;
				error = puffs_mappedread(vp, uio);
				if (error)
					break;
				if (tomove != uio->uio_resid)
					continue;
				/*
				 * Page lookup failed.
				 * Unlock vnode and perform uncached read
				 */
				puffs_unlockvnode(pn, &ltype);
				vplocked = 0;
			}
			puffs_msgpark_reset(park_read);
			tomove = PUFFS_TOMOVE(uio->uio_resid, pmp);
			if (mapped)
				tomove = MIN(tomove,
				    PAGE_SIZE - (uio->uio_offset & PAGE_MASK));
			memset(read_msg, 0, argsize); /* XXX: touser KASSERT */
			RWARGS(read_msg, ap->a_ioflag, tomove,
			    uio->uio_offset, ap->a_cred);
			puffs_msg_setinfo(park_read, PUFFSOP_VN,
			    PUFFS_VN_READ, VPTOPNC(vp));
			puffs_msg_setdelta(park_read, tomove);

			PUFFS_MSG_ENQUEUEWAIT2(pmp, park_read, vp->v_data,
			    NULL, error);
			error = checkerr(pmp, error, __func__);
			if (error)
				break;

			if (read_msg->pvnr_resid > tomove) {
				puffs_senderr(pmp, PUFFS_ERR_READ,
				    E2BIG, "resid grew", VPTOPNC(ap->a_vp));
				error = EPROTO;
				break;
			}

			error = uiomove(read_msg->pvnr_data,
			    tomove - read_msg->pvnr_resid, uio);

			/*
			 * in case the file is out of juice, resid from
			 * userspace is != 0.  and the error-case is
			 * quite obvious
			 */
			if (error || read_msg->pvnr_resid)
				break;
			if (mapped) {
				ASSERT_VOP_UNLOCKED(vp, "puffs_vnop_read");
				PUFFS_LOCKVNODE(pn, ltype, error);
				if (error != 0)
					break;
				vplocked = 1;
			}
		}
		puffs_msgmem_release(park_read);
		if (!vplocked)
			PUFFS_LOCKVNODE(pn, ltype, error);
	}

	return error;
}

/*
 * XXX: in case of a failure, this leaves uio in a bad state.
 * We could theoretically copy the uio and iovecs and "replay"
 * them the right amount after the userspace trip, but don't
 * bother for now.
 */
static int
puffs_vnop_write(struct vop_write_args *ap)
{
	PUFFS_MSG_VARS(vn, write);
	struct vnode *vp = ap->a_vp;
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	struct puffs_node *pn = VPTOPP(vp);
	struct uio *uio = ap->a_uio;
	size_t tomove, argsize;
	int ltype;
	int error, uflags;
#ifdef XXX_TS
	off_t oldoff, newoff, origoff;
	size_t bytelen;
	int ubcflags;
#endif
	off_t offset;
	int mapped, vplocked;

	error = uflags = 0;
	write_msg = NULL;

	if (0 && vp->v_type == VREG && PUFFS_USE_PAGECACHE(pmp)) {
		return EIO;
#ifdef XXX_TS
		ubcflags = UBC_WRITE | UBC_PARTIALOK | UBC_UNMAP_FLAG(vp);

		/*
		 * userspace *should* be allowed to control this,
		 * but with UBC it's a bit unclear how to handle it
		 */
		if (ap->a_ioflag & IO_APPEND)
			uio->uio_offset = vp->v_size;

		origoff = uio->uio_offset;
		while (uio->uio_resid > 0) {
			uflags |= PUFFS_UPDATECTIME;
			uflags |= PUFFS_UPDATEMTIME;
			oldoff = uio->uio_offset;
			bytelen = uio->uio_resid;

			newoff = oldoff + bytelen;
			if (vp->v_size < newoff) {
				vnode_pager_setsize(vp, newoff);
			}
			error = ubc_uiomove(&vp->v_uobj, uio, bytelen,
			    UVM_ADV_RANDOM, ubcflags);

			/*
			 * In case of a ubc_uiomove() error,
			 * opt to not extend the file at all and
			 * return an error.  Otherwise, if we attempt
			 * to clear the memory we couldn't fault to,
			 * we might generate a kernel page fault.
			 */
			if (vp->v_size < newoff) {
				if (error == 0) {
					uflags |= PUFFS_UPDATESIZE;
					vnode_pager_setsize(vp, newoff);
				} else {
					vnode_pager_setsize(vp, vp->v_size);
				}
			}
			if (error)
				break;

			/*
			 * If we're writing large files, flush to file server
			 * every 64k.  Otherwise we can very easily exhaust
			 * kernel and user memory, as the file server cannot
			 * really keep up with our writing speed.
			 *
			 * Note: this does *NOT* honor MNT_ASYNC, because
			 * that gives userland too much say in the kernel.
			 */
			if (oldoff >> 16 != uio->uio_offset >> 16) {
				mtx_lock(&vp->v_interlock);
				error = VOP_PUTPAGES(vp, oldoff & ~0xffff,
				    uio->uio_offset & ~0xffff,
				    PGO_CLEANIT | PGO_SYNCIO);
				if (error)
					break;
			}
		}

		/* synchronous I/O? */
		if (error == 0 && ap->a_ioflag & IO_SYNC) {
			mtx_lock(&vp->v_interlock);
			error = VOP_PUTPAGES(vp, trunc_page(origoff),
			    round_page(uio->uio_offset),
			    PGO_CLEANIT | PGO_SYNCIO);

		/* write through page cache? */
		} else if (error == 0 && pmp->pmp_flags & PUFFS_KFLAG_WTCACHE) {
			mtx_lock(&vp->v_interlock);
			error = VOP_PUTPAGES(vp, trunc_page(origoff),
			    round_page(uio->uio_offset), PGO_CLEANIT);
		}

		puffs_updatenode(VPTOPP(vp), uflags, vp->v_size);
#endif
	} else {
		mapped = puffs_ismapped(vp);
		vplocked = 1;
		if (!mapped) {
			puffs_unlockvnode(pn, &ltype);
			vplocked = 0;
		}

		/* tomove is non-increasing */
		/* puffs_mappedwrite expects at least PAGE_SIZE bytes */
		tomove = PUFFS_TOMOVE(MAX(uio->uio_resid, PAGE_SIZE), pmp);
		argsize = sizeof(struct puffs_vnmsg_write) + tomove;
		puffs_msgmem_alloc(argsize, &park_write, (void *)&write_msg,1);

		while (uio->uio_resid > 0) {
			/* move data to buffer */
			offset = uio->uio_offset;
			puffs_msgpark_reset(park_write);
			memset(write_msg, 0, argsize); /* XXX: touser KASSERT */
			if (mapped) {
				if (!vplocked) {
					PUFFS_LOCKVNODE(pn, ltype, error);
					if (error)
						break;
					vplocked = 1;
				}
				tomove = uio->uio_resid;
				error = puffs_mappedwrite(vp, uio,
				    write_msg->pvnr_data);
				if (error)
					break;
				tomove -= uio->uio_resid;
				MPASS(tomove >= 0 && tomove <= PAGE_SIZE);
				puffs_unlockvnode(pn, &ltype);
				vplocked = 0;
				if (tomove > 0)
					goto lowerwrite;
			}
			tomove = PUFFS_TOMOVE(uio->uio_resid, pmp);
			if (mapped)
				tomove = MIN(tomove,
				    PAGE_SIZE - (offset & PAGE_MASK));
			error = uiomove(write_msg->pvnr_data, tomove, uio);
			if (error)
				break;

lowerwrite:
			ASSERT_VOP_UNLOCKED(vp, "puffs_mappedwrite");
			RWARGS(write_msg, ap->a_ioflag, tomove,
			    offset, ap->a_cred);
			/* move buffer to userspace */
			puffs_msg_setinfo(park_write, PUFFSOP_VN,
			    PUFFS_VN_WRITE, VPTOPNC(vp));
			PUFFS_MSG_ENQUEUEWAIT2(pmp, park_write, vp->v_data,
			    NULL, error);
			error = checkerr(pmp, error, __func__);
			if (error)
				break;

			if (write_msg->pvnr_resid > tomove) {
				puffs_senderr(pmp, PUFFS_ERR_WRITE,
				    E2BIG, "resid grew", VPTOPNC(ap->a_vp));
				error = EPROTO;
				break;
			}

			/* adjust file size */
			if (vp->v_object != NULL) {
				vm_ooffset_t osize;
				vm_object_t object = vp->v_object;
				VM_OBJECT_LOCK(object);
				osize = object->un_pager.vnp.vnp_size;
				VM_OBJECT_UNLOCK(object);
				if (osize < uio->uio_offset) {
					PUFFS_LOCKVNODE(pn, ltype, error);
					if (error)
						break;
					vplocked = 1;
					vnode_pager_setsize(vp,
					    uio->uio_offset);
					puffs_unlockvnode(pn, &ltype);
					vplocked = 0;
					/* There is no more mapped pages left */
					mapped = 0;
				}
			}

			/* didn't move everything?  bad userspace.  bail */
			if (write_msg->pvnr_resid != 0) {
				error = EIO;
				break;
			}
		}
		puffs_msgmem_release(park_write);
		if (!vplocked)
			PUFFS_LOCKVNODE(pn, ltype, error);
	}

	return error;
}

static int
puffs_vnop_print(struct vop_print_args *ap)
{
	PUFFS_MSG_VARS(vn, print);
	struct vnode *vp = ap->a_vp;
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	struct puffs_node *pn = vp->v_data;
	int ltype;
	int error;

	/* kernel portion */
	printf("tag VT_PUFFS, vnode %p, puffs node: %p,\n"
	    "    userspace cookie: %p\n", vp, pn, pn->pn_cookie);
	KASSERT(vp->v_type != VFIFO, ("v_type != VFIFO"));

	/* userspace portion */
	if (EXISTSOP(pmp, PRINT)) {
		PUFFS_MSG_ALLOC(vn, print);
		puffs_msg_setinfo(park_print, PUFFSOP_VN,
		    PUFFS_VN_PRINT, VPTOPNC(vp));
		puffs_msg_enqueue(pmp, park_print);
		puffs_unlockvnode(pn, &ltype);
		error = puffs_msg_wait2(pmp, park_print, pn, NULL);
		PUFFS_MSG_RELEASE(print);
		PUFFS_LOCKVNODE(pn, ltype, error);
	}

	return 0;
}

static int
puffs_vnop_pathconf(struct vop_pathconf_args *ap)
{
	PUFFS_MSG_VARS(vn, pathconf);
	struct vnode *vp = ap->a_vp;
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	struct puffs_node *pn = vp->v_data;
	int ltype;
	int error;

	if (!EXISTSOP(pmp, PATHCONF))
		return EINVAL;

	PUFFS_MSG_ALLOC(vn, pathconf);
	pathconf_msg->pvnr_name = ap->a_name;
	puffs_msg_setinfo(park_pathconf, PUFFSOP_VN,
	    PUFFS_VN_PATHCONF, VPTOPNC(vp));
	puffs_msg_enqueue(pmp, park_pathconf);
	puffs_unlockvnode(pn, &ltype);
	error = puffs_msg_wait2(pmp, park_pathconf, pn, NULL);
	error = checkerr(pmp, error, __func__);
	PUFFS_LOCKVNODE(pn, ltype, error);

	if (!error)
		*ap->a_retval = pathconf_msg->pvnr_retval;
	PUFFS_MSG_RELEASE(pathconf);

	return error;
}

static int
puffs_vnop_advlock(struct vop_advlock_args *ap)
{
	PUFFS_MSG_VARS(vn, advlock);
	struct vnode *vp = ap->a_vp;
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	struct puffs_node *pn = VPTOPP(vp);
	int ltype;
	int error;

	PUFFS_MSG_ALLOC(vn, advlock);
	error = copyin(ap->a_fl, &advlock_msg->pvnr_fl, sizeof(struct flock));
	if (error)
		goto out;
	advlock_msg->pvnr_id = ap->a_id;
	advlock_msg->pvnr_op = ap->a_op;
	advlock_msg->pvnr_flags = ap->a_flags;
	puffs_msg_setinfo(park_advlock, PUFFSOP_VN,
	    PUFFS_VN_ADVLOCK, VPTOPNC(vp));

	puffs_msg_enqueue(pmp, park_advlock);
	puffs_unlockvnode(pn, &ltype);
	error = puffs_msg_wait2(pmp, park_advlock, pn, NULL);
	error = checkerr(pmp, error, __func__);
	PUFFS_LOCKVNODE(pn, ltype, error);

 out:
	PUFFS_MSG_RELEASE(advlock);
	return error;
}

#ifdef XXX_TS
#define BIOASYNC(bp) (bp->b_flags & B_ASYNC)

/*
 * This maps itself to PUFFS_VN_READ/WRITE for data transfer.
 */
static int
puffs_vnop_strategy(struct vop_strategy_args *ap)
{
	PUFFS_MSG_VARS(vn, rw);
	struct vnode *vp = ap->a_vp;
	struct puffs_mount *pmp = MPTOPUFFSMP(vp->v_mount);
	struct puffs_node *pn;
	struct buf *bp;
	size_t argsize;
	size_t tomove, moved;
	int error, dofaf, dobiodone;

	pmp = MPTOPUFFSMP(vp->v_mount);
	bp = ap->a_bp;
	error = 0;
	dofaf = 0;
	pn = VPTOPP(vp);
	park_rw = NULL; /* explicit */
	dobiodone = 1;

	if ((bp->b_iocmd == BIO_READ && !EXISTSOP(pmp, READ))
	    || (bp->b_iocmd == BIO_WRITE && !EXISTSOP(pmp, WRITE)))
		ERROUT(EOPNOTSUPP);

#ifdef DIAGNOSTIC
	if (bp->b_bcount > pmp->pmp_msg_maxsize - PUFFS_MSGSTRUCT_MAX)
		panic("puffs_strategy: wildly inappropriate buf bcount %d",
		    bp->b_bcount);
#endif

	/*
	 * See explanation for the necessity of a FAF in puffs_fsync.
	 *
	 * Also, do FAF in case we're suspending.
	 * See puffs_vfsops.c:pageflush()
	 */
	if (bp->b_iocmd == BIO_WRITE) {
#ifdef XXX_TS
		mtx_lock(&vp->v_interlock);
		if (vp->v_iflag & VI_XLOCK)
			dofaf = 1;
		if (pn->pn_stat & PNODE_SUSPEND)
			dofaf = 1;
		mtx_unlock(&vp->v_interlock);
#endif
	}

#ifdef DIAGNOSTIC
		if (curlwp == uvm.pagedaemon_lwp)
			KASSERT(dofaf || BIOASYNC(bp));
#endif

	/* allocate transport structure */
	tomove = PUFFS_TOMOVE(bp->b_bcount, pmp);
	argsize = sizeof(struct puffs_vnmsg_rw);
	error = puffs_msgmem_alloc(argsize + tomove, &park_rw,
	    (void *)&rw_msg, dofaf ? 0 : 1);
	if (error)
		goto out;
	RWARGS(rw_msg, 0, tomove, bp->b_blkno << DEV_BSHIFT, FSCRED);

	/* 2x2 cases: read/write, faf/nofaf */
	if (bp->b_iocmd == BIO_READ) {
		puffs_msg_setinfo(park_rw, PUFFSOP_VN,
		    PUFFS_VN_READ, VPTOPNC(vp));
		puffs_msg_setdelta(park_rw, tomove);
#ifdef XXX_TS
		if (BIOASYNC(bp)) {
			puffs_msg_setcall(park_rw,
			    puffs_parkdone_asyncbioread, bp);
			puffs_msg_enqueue(pmp, park_rw);
			dobiodone = 0;
		} else {
#else
		if (1) {
#endif
			PUFFS_MSG_ENQUEUEWAIT2(pmp, park_rw, vp->v_data,
			    NULL, error);
			error = checkerr(pmp, error, __func__);
			if (error)
				goto out;

			if (rw_msg->pvnr_resid > tomove) {
				puffs_senderr(pmp, PUFFS_ERR_READ,
				    E2BIG, "resid grew", VPTOPNC(vp));
				ERROUT(EPROTO);
			}

			moved = tomove - rw_msg->pvnr_resid;

			(void)memcpy(bp->b_data, rw_msg->pvnr_data, moved);
			bp->b_resid = bp->b_bcount - moved;
		}
	} else {
		puffs_msg_setinfo(park_rw, PUFFSOP_VN,
		    PUFFS_VN_WRITE, VPTOPNC(vp));
		/*
		 * make pages read-only before we write them if we want
		 * write caching info
		 */
#ifdef XXX_TS
		if (PUFFS_WCACHEINFO(pmp)) {
			struct uvm_object *uobj = &vp->v_uobj;
			int npages = (bp->b_bcount + PAGE_SIZE-1) >> PAGE_SHIFT;
			struct vm_page *vmp;
			int i;

			for (i = 0; i < npages; i++) {
				vmp= uvm_pageratop((vaddr_t)bp->b_data
				    + (i << PAGE_SHIFT));
				DPRINTF(("puffs_strategy: write-protecting "
				    "vp %p page %p, offset %" PRId64"\n",
				    vp, vmp, vmp->offset));
				mtx_lock(&uobj->vmobjlock);
				vmp->flags |= PG_RDONLY;
				pmap_page_protect(vmp, VM_PROT_READ);
				mtx_unlock(&uobj->vmobjlock);
			}
		}
#endif

		(void)memcpy(&rw_msg->pvnr_data, bp->b_data, tomove);
		if (dofaf) {
			puffs_msg_setfaf(park_rw);
		} else if (BIOASYNC(bp)) {
			puffs_msg_setcall(park_rw,
			    puffs_parkdone_asyncbiowrite, bp);
			dobiodone = 0;
		}

		PUFFS_MSG_ENQUEUEWAIT2(pmp, park_rw, vp->v_data, NULL, error);

		if (dobiodone == 0)
			goto out;

		/*
		 * XXXXXXXX: wrong, but kernel can't survive strategy
		 * failure currently.  Here, have one more X: X.
		 */
		if (error != ENOMEM)
			error = 0;

		error = checkerr(pmp, error, __func__);
		if (error)
			goto out;

		if (rw_msg->pvnr_resid > tomove) {
			puffs_senderr(pmp, PUFFS_ERR_WRITE,
			    E2BIG, "resid grew", VPTOPNC(vp));
			ERROUT(EPROTO);
		}

		/*
		 * FAF moved everything.  Frankly, we don't
		 * really have a choice.
		 */
		if (dofaf && error == 0)
			moved = tomove;
		else
			moved = tomove - rw_msg->pvnr_resid;

		bp->b_resid = bp->b_bcount - moved;
		if (bp->b_resid != 0) {
			ERROUT(EIO);
		}
	}

 out:
	if (park_rw)
		puffs_msgmem_release(park_rw);

	if (error)
		bp->b_error = error;

	if (error || dobiodone)
		bdone(bp);

	return error;
}
#endif

static int
puffs_fifo_close(struct vop_close_args *ap)
{
	puffs_updatenode(VPTOPP(ap->a_vp), PUFFS_UPDATEATIME | PUFFS_UPDATEMTIME, 0);
	return fifo_specops.vop_close(ap);
}


/*
 * vnode operations vector
 */

struct vop_vector puffs_vnodeops = {
	.vop_default =			&default_vnodeops,
	.vop_lookup =			puffs_vnop_lookup,
	.vop_create =			puffs_vnop_create,
	.vop_mknod =			puffs_vnop_mknod,
	.vop_open =			puffs_vnop_open,
	.vop_close =			puffs_vnop_close,
	.vop_access =			puffs_vnop_access,
	.vop_advlock =			puffs_vnop_advlock,
	.vop_getattr =			puffs_vnop_getattr,
	.vop_setattr =			puffs_vnop_setattr,
	.vop_read =			puffs_vnop_read,
	.vop_write =			puffs_vnop_write,
	.vop_fsync =			puffs_vnop_fsync,
	.vop_remove =			puffs_vnop_remove,
	.vop_link =			puffs_vnop_link,
	.vop_rename =			puffs_vnop_rename,
	.vop_mkdir =			puffs_vnop_mkdir,
	.vop_rmdir =			puffs_vnop_rmdir,
	.vop_symlink =			puffs_vnop_symlink,
	.vop_readdir =			puffs_vnop_readdir,
	.vop_readlink =			puffs_vnop_readlink,
	.vop_inactive =			puffs_vnop_inactive,
	.vop_reclaim =			puffs_vnop_reclaim,
	.vop_print =			puffs_vnop_print,
	.vop_pathconf =			puffs_vnop_pathconf,
	.vop_vptofh =			puffs_vnop_vptofh,
	.vop_strategy =			VOP_PANIC,
	.vop_bmap =			VOP_EOPNOTSUPP,
	.vop_getpages =			vop_stdgetpages,
	.vop_putpages =			vop_stdputpages,
};

/*
 * fifo operations vector
 */

struct vop_vector puffs_fifoops = {
	.vop_default =		&fifo_specops,
	.vop_access =		puffs_vnop_access,
	.vop_getattr =		puffs_vnop_getattr,
	.vop_inactive =		puffs_vnop_inactive,
	.vop_reclaim =		puffs_vnop_reclaim,
	.vop_setattr =		puffs_vnop_setattr,
	.vop_close =		puffs_fifo_close,
};
