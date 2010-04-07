/*	$NetBSD: puffs_node.c,v 1.13 2008/05/06 12:33:16 ad Exp $	*/

/*
 * Copyright (c) 2005, 2006, 2007  Antti Kantee.  All Rights Reserved.
 *
 * Development of this software was supported by the
 * Google Summer of Code program, the Ulla Tuominen Foundation
 * and the Finnish Cultural Foundation.
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
__KERNEL_RCSID(0, "$NetBSD: puffs_node.c,v 1.13 2008/05/06 12:33:16 ad Exp $");
*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/hash.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>

#include <vm/uma.h>
#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vm_extern.h>

#include <puffs_msgif.h>
#include <puffs_sys.h>

static __inline struct puffs_node_hashlist
	*puffs_cookie2hashlist(struct puffs_mount *, puffs_cookie_t);
static struct puffs_node *puffs_cookie2pnode(struct puffs_mount *,
					     puffs_cookie_t);

uma_zone_t puffs_pnpool;


/*
 * Flush VM pages associtaed with vnode
 */
void
puffs_flushvnode(struct vnode *vp)
{
	if (vp->v_object) {
		VM_OBJECT_LOCK(vp->v_object);
		vm_object_page_clean(vp->v_object, 0, 0, OBJPC_SYNC);
		VM_OBJECT_UNLOCK(vp->v_object);
	}
}

/*
 * Grab a vnode, intialize all the puffs-dependant stuff.
 */
int
puffs_getvnode(struct mount *mp, puffs_cookie_t ck, enum vtype type,
	off_t vsize, dev_t rdev, int lkflag, struct vnode **vpp)
{
	struct puffs_mount *pmp;
	struct puffs_newcookie *pnc;
	struct vnode *vp;
	struct puffs_node *pnode;
	struct puffs_node_hashlist *plist;
	int error;

	KASSERT(mp != NULL, ("mp == NULL"));

	pmp = MPTOPUFFSMP(mp);

	error = EPROTO;
	if (type <= VNON || type >= VBAD) {
		puffs_senderr(pmp, PUFFS_ERR_MAKENODE, EINVAL,
		    "bad node type", ck);
		goto bad;
	}
	if (vsize == VNOVAL) {
		puffs_senderr(pmp, PUFFS_ERR_MAKENODE, EINVAL,
		    "VSIZENOTSET is not a valid size", ck);
		goto bad;
	}

	pnode = uma_zalloc(puffs_pnpool, M_WAITOK | M_ZERO);

	error = getnewvnode("puffs", mp, &puffs_vnodeops, &vp);
	if (error) {
		uma_zfree(puffs_pnpool, pnode);
		goto bad;
	}
	vn_lock(vp, lkflag | LK_RETRY);
	error = insmntque(vp, mp);
	if (error) {
		vp = NULL;
		uma_zfree(puffs_pnpool, pnode);
		goto bad;
	}

	/*
	 * Creation should not fail after this point.  Or if it does,
	 * care must be taken so that VOP_INACTIVE() isn't called.
	 */

	switch (type) {
	case VCHR:
	case VBLK:
	case VDIR:
	case VLNK:
	case VSOCK:
		break;
	case VFIFO:
		vp->v_op = &puffs_fifoops;
		break;
	case VREG:
		vnode_pager_setsize(vp, vsize);
		break;
	default:
		panic("puffs_getvnode: invalid vtype %d", type);
	}

	pnode->pn_cookie = ck;
	pnode->pn_refcount = 1;

	/* insert cookie on list, take off of interlock list */
	mtx_init(&pnode->pn_mtx, "puffs pn_mtx", NULL, MTX_DEF);
	knlist_init(&pnode->pn_sel.si_note, NULL, NULL, NULL, NULL, NULL);
	plist = puffs_cookie2hashlist(pmp, ck);
	mtx_lock(&pmp->pmp_lock);
	LIST_INSERT_HEAD(plist, pnode, pn_hashent);
	if (ck != pmp->pmp_root_cookie) {
		LIST_FOREACH(pnc, &pmp->pmp_newcookie, pnc_entries) {
			if (pnc->pnc_cookie == ck) {
				LIST_REMOVE(pnc, pnc_entries);
				free(pnc, M_PUFFS);
				break;
			}
		}
		KASSERT(pnc != NULL, ("pnc != NULL"));
	}
	mtx_unlock(&pmp->pmp_lock);

	vp->v_data = pnode;
	vp->v_type = type;
	pnode->pn_vp = vp;
	pnode->pn_serversize = vsize;

	*vpp = vp;

	DPRINTF(("new vnode at %p, pnode %p, cookie %p\n", vp,
	    pnode, pnode->pn_cookie));
	ASSERT_VI_UNLOCKED(vp, "puffs_getvnode");

	return 0;

 bad:
	/* remove staging cookie from list */
	if (ck != pmp->pmp_root_cookie) {
		mtx_lock(&pmp->pmp_lock);
		LIST_FOREACH(pnc, &pmp->pmp_newcookie, pnc_entries) {
			if (pnc->pnc_cookie == ck) {
				LIST_REMOVE(pnc, pnc_entries);
				free(pnc, M_PUFFS);
				break;
			}
		}
		KASSERT(pnc != NULL, ("pnc != NULL"));
		mtx_unlock(&pmp->pmp_lock);
	}

	return error;
}

/* new node creating for creative vop ops (create, symlink, mkdir, mknod) */
int
puffs_newnode(struct mount *mp, struct vnode *dvp, struct vnode **vpp,
	puffs_cookie_t ck, struct componentname *cnp,
	enum vtype type, dev_t rdev)
{
	struct puffs_mount *pmp;
	struct puffs_newcookie *pnc, *npnc;
	struct vnode *vp;
	int error;

	KASSERT(mp != NULL, ("mp == NULL"));
	pmp = MPTOPUFFSMP(mp);

	/* userspace probably has this as a NULL op */
	if (ck == NULL) {
		error = EOPNOTSUPP;
		return error;
	}

	/*
	 * Check for previous node with the same designation.
	 * Explicitly check the root node cookie, since it might be
	 * reclaimed from the kernel when this check is made.
	 */
	mtx_lock(&pmp->pmp_lock);
	if (ck == pmp->pmp_root_cookie
	    || puffs_cookie2pnode(pmp, ck) != NULL) {
		mtx_unlock(&pmp->pmp_lock);
		puffs_senderr(pmp, PUFFS_ERR_MAKENODE, EEXIST,
		    "cookie exists", ck);
		return EPROTO;
	}
	mtx_unlock(&pmp->pmp_lock);

	npnc = malloc(sizeof(struct puffs_newcookie), M_PUFFS, M_WAITOK);
	npnc->pnc_cookie = ck;

	mtx_lock(&pmp->pmp_lock);
	LIST_FOREACH(pnc, &pmp->pmp_newcookie, pnc_entries) {
		if (pnc->pnc_cookie == ck) {
			mtx_unlock(&pmp->pmp_lock);
			free(npnc, M_PUFFS);
			puffs_senderr(pmp, PUFFS_ERR_MAKENODE, EEXIST,
			    "cookie exists", ck);
			return EPROTO;
		}
	}
	LIST_INSERT_HEAD(&pmp->pmp_newcookie, npnc, pnc_entries);
	mtx_unlock(&pmp->pmp_lock);

	error = puffs_getvnode(dvp->v_mount, ck, type, 0, rdev, LK_EXCLUSIVE, &vp);
	if (error)
		return error;

	vp->v_type = type;
	*vpp = vp;

	if ((cnp->cn_flags & MAKEENTRY) && PUFFS_USE_NAMECACHE(pmp))
		cache_enter(dvp, vp, cnp);

	return 0;
}

void
puffs_putvnode(struct vnode *vp)
{
	struct puffs_node *pnode;

	pnode = VPTOPP(vp);

	LIST_REMOVE(pnode, pn_hashent);
	vnode_destroy_vobject(vp);
	puffs_releasenode(pnode);
	vp->v_data = NULL;

	return;
}

static __inline struct puffs_node_hashlist *
puffs_cookie2hashlist(struct puffs_mount *pmp, puffs_cookie_t ck)
{
	uint32_t hash;

	hash = hash32_buf(&ck, sizeof(void *), HASHINIT);
	return &pmp->pmp_pnodehash[hash % pmp->pmp_npnodehash];
}

/*
 * Translate cookie to puffs_node.  Caller must hold pmp_lock
 * and it will be held upon return.
 */
static struct puffs_node *
puffs_cookie2pnode(struct puffs_mount *pmp, puffs_cookie_t ck)
{
	struct puffs_node_hashlist *plist;
	struct puffs_node *pnode;

	plist = puffs_cookie2hashlist(pmp, ck);
	LIST_FOREACH(pnode, plist, pn_hashent) {
		if (pnode->pn_cookie == ck)
			break;
	}

	return pnode;
}

/*
 * Make sure root vnode exists and reference it.  Does NOT lock.
 */
static int
puffs_makeroot(struct puffs_mount *pmp, int lkflag)
{
	struct vnode *vp;
	int rv;

	/*
	 * pmp_lock must be held if vref()'ing or vrele()'ing the
	 * root vnode.  the latter is controlled by puffs_inactive().
	 *
	 * pmp_root is set here and cleared in puffs_reclaim().
	 */
 retry:
	mtx_lock(&pmp->pmp_lock);
	vp = pmp->pmp_root;
	if (vp) {
		VI_LOCK(vp);
		mtx_unlock(&pmp->pmp_lock);
		vholdl(vp);
		vget(vp, lkflag | LK_INTERLOCK | LK_RETRY, curthread);
		vdrop(vp);
		ASSERT_VI_UNLOCKED(vp, "puffs_makeroot");

		return 0;
	} else {
		mtx_unlock(&pmp->pmp_lock);
	}

	/*
	 * So, didn't have the magic root vnode available.
	 * No matter, grab another and stuff it with the cookie.
	 */
	if ((rv = puffs_getvnode(pmp->pmp_mp, pmp->pmp_root_cookie,
	    pmp->pmp_root_vtype, pmp->pmp_root_vsize, pmp->pmp_root_rdev, lkflag, &vp)))
		return rv;

	/*
	 * Someone magically managed to race us into puffs_getvnode?
	 * Put our previous new vnode back and retry.
	 */
	mtx_lock(&pmp->pmp_lock);
	if (pmp->pmp_root) {
		mtx_unlock(&pmp->pmp_lock);
		puffs_putvnode(vp);
		goto retry;
	}

	/* store cache */
	vp->v_vflag |= VV_ROOT;
	pmp->pmp_root = vp;
	mtx_unlock(&pmp->pmp_lock);
	ASSERT_VI_UNLOCKED(vp, "puffs_makeroot");

	return 0;
}

/*
 * Locate the in-kernel vnode based on the cookie received given
 * from userspace.  Returns a vnode, if found, NULL otherwise.
 * The parameter "lock" control whether to lock the possible or
 * not.  Locking always might cause us to lock against ourselves
 * in situations where we want the vnode but don't care for the
 * vnode lock, e.g. file server issued putpages.
 */
int
puffs_cookie2vnode(struct puffs_mount *pmp, puffs_cookie_t ck, int lkflag,
	int willcreate, struct vnode **vpp)
{
	struct puffs_node *pnode;
	struct puffs_newcookie *pnc;
	struct vnode *vp;
	int rv;

	/*
	 * Handle root in a special manner, since we want to make sure
	 * pmp_root is properly set.
	 */
	if (ck == pmp->pmp_root_cookie) {
		if ((rv = puffs_makeroot(pmp, lkflag)))
			return rv;
		*vpp = pmp->pmp_root;
		return 0;
	}

	mtx_lock(&pmp->pmp_lock);
	pnode = puffs_cookie2pnode(pmp, ck);
	if (pnode == NULL) {
		mtx_unlock(&pmp->pmp_lock);
		if (willcreate) {
			pnc = malloc(sizeof(struct puffs_newcookie),
			    M_PUFFS, M_WAITOK);
			pnc->pnc_cookie = ck;
			mtx_lock(&pmp->pmp_lock);
			LIST_INSERT_HEAD(&pmp->pmp_newcookie, pnc, pnc_entries);
			mtx_unlock(&pmp->pmp_lock);
		}
		return PUFFS_NOSUCHCOOKIE;
	}
	vp = pnode->pn_vp;
	VI_LOCK(vp);
	mtx_unlock(&pmp->pmp_lock);

	vget(vp, lkflag | LK_INTERLOCK | LK_RETRY, curthread);

	*vpp = vp;
	return 0;
}

void
puffs_updatenode(struct puffs_node *pn, int flags, off_t size)
{
	struct timespec ts;

	if (flags == 0)
		return;

	nanotime(&ts);

	mtx_lock(&pn->pn_mtx);
	if (flags & PUFFS_UPDATEATIME) {
		pn->pn_mc_atime = ts;
		pn->pn_stat |= PNODE_METACACHE_ATIME;
	}
	if (flags & PUFFS_UPDATECTIME) {
		pn->pn_mc_ctime = ts;
		pn->pn_stat |= PNODE_METACACHE_CTIME;
	}
	if (flags & PUFFS_UPDATEMTIME) {
		pn->pn_mc_mtime = ts;
		pn->pn_stat |= PNODE_METACACHE_MTIME;
	}
	if (flags & PUFFS_UPDATESIZE) {
		pn->pn_mc_size = size;
		pn->pn_stat |= PNODE_METACACHE_SIZE;
	}
	mtx_unlock(&pn->pn_mtx);
}

/*
 * Add reference to node.
 *  mutex held on entry and return
 */
void
puffs_referencenode(struct puffs_node *pn)
{

	mtx_assert(&pn->pn_mtx, MA_OWNED);
	pn->pn_refcount++;
}

/*
 * Release pnode structure which dealing with references to the
 * puffs_node instead of the vnode.  Can't use vref()/vrele() on
 * the vnode there, since that causes the lovely VOP_INACTIVE(),
 * which in turn causes the lovely deadlock when called by the one
 * who is supposed to handle it.
 */
void
puffs_releasenode(struct puffs_node *pn)
{

	mtx_lock(&pn->pn_mtx);
	if (--pn->pn_refcount == 0) {
		DPRINTF(("puffs_releasenode: destroy puffs_node pn_vp=%p\n", pn->pn_vp));
		mtx_unlock(&pn->pn_mtx);
		mtx_destroy(&pn->pn_mtx);
		knlist_destroy(&pn->pn_sel.si_note);
		uma_zfree(puffs_pnpool, pn);
	} else {
		mtx_unlock(&pn->pn_mtx);
	}
}

int
puffs_lockvnode(struct puffs_node *pn, int ltype)
{
	struct vnode *vp;

	KASSERT(pn != NULL, ("invalid node"));
	vp = pn->pn_vp;
	KASSERT(vp != NULL, ("invalid vnode"));
	ASSERT_VOP_UNLOCKED(vp, "puffs_lockvnode");

	vrele(vp);
	vn_lock(vp, (ltype & LK_TYPE_MASK) | LK_RETRY);
	ASSERT_VOP_LOCKED(vp, "puffs_lockvnode");
	puffs_releasenode(pn);
	if (vp->v_iflag & VI_DOOMED) {
		DPRINTF(("puffs_lockvnode: vnode is dead %p\n", vp));
		return EBADF;
	}
	return 0;
}

int
puffs_unlockvnode(struct puffs_node *pn, int *ltype)
{
	struct vnode *vp;
	int error;

	KASSERT(pn != NULL, ("invalid node"));
	vp = pn->pn_vp;
	KASSERT(vp != NULL, ("invalid vnode"));
	ASSERT_VOP_LOCKED(vp, "puffs_unlockvnode");

	mtx_lock(&pn->pn_mtx);
	puffs_referencenode(pn);
	mtx_unlock(&pn->pn_mtx);
	vref(vp);
	if (ltype)
		*ltype = VOP_ISLOCKED(vp);
	error = VOP_UNLOCK(vp, 0);
	ASSERT_VOP_UNLOCKED(vp, "puffs_unlockvnode");
	return error;
}

