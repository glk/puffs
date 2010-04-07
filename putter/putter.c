/*	$NetBSD: putter.c,v 1.23 2009/04/11 23:05:26 christos Exp $	*/

/*
 * Copyright (c) 2006, 2007  Antti Kantee.  All Rights Reserved.
 *
 * Development of this software was supported by the
 * Ulla Tuominen Foundation and the Finnish Cultural Foundation and the
 * Research Foundation of Helsinki University of Technology
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

/*
 * Pass-to-Userspace TransporTER: generic kernel-user request-response
 * transport interface.
 */

#include <sys/cdefs.h>
/*
__KERNEL_RCSID(0, "$NetBSD: putter.c,v 1.16 2008/08/08 13:02:10 pooka Exp $");
*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/poll.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/selinfo.h>
#include <sys/uio.h>

#include <putter_sys.h>

#define DEVICE_NAME	"putter"

static MALLOC_DEFINE(M_PUTTER, DEVICE_NAME, "Putter device data");

static struct clonedevs *putter_dev_clones = NULL;

/*
 * putter instance structures.  these are always allocated and freed
 * from the context of the transport user.
 */
struct putter_instance {
	pid_t			pi_pid;
	int			pi_idx;	/* device unit number */
	struct selinfo		pi_sel;

	void			*pi_private;
	struct putter_ops	*pi_pop;

	uint8_t			*pi_curput;
	size_t			pi_curres;
	void			*pi_curopaq;

	TAILQ_ENTRY(putter_instance) pi_entries;
};
#define PUTTER_EMBRYO ((void *)-1)	/* before attach	*/
#define PUTTER_DEAD ((void *)-2)	/* after detach		*/

static TAILQ_HEAD(, putter_instance) putter_ilist
    = TAILQ_HEAD_INITIALIZER(putter_ilist);

#ifdef DEBUG
#ifndef PUTTERDEBUG
#define PUTTERDEBUG
#endif
#endif

#ifdef PUTTERDEBUG
int putterdebug = 1;
#define DPRINTF(x) if (putterdebug > 0) printf x
#define DPRINTF_VERBOSE(x) if (putterdebug > 1) printf x
#else
#define DPRINTF(x)
#define DPRINTF_VERBOSE(x)
#endif

/*
 * public init / deinit
 */

/* protects both the list and the contents of the list elements */
static struct mtx pi_mtx;

static int
putter_fop_read(struct cdev *dev, struct uio *uio, int flags)
{
	struct putter_instance *pi = dev->si_drv1;
	size_t origres, moved;
	int error;

	if (pi->pi_private == PUTTER_EMBRYO || pi->pi_private == PUTTER_DEAD) {
		printf("putter_fop_read: private %d not inited\n", pi->pi_idx);
		return ENOENT;
	}

	if (pi->pi_curput == NULL) {
		error = pi->pi_pop->pop_getout(pi->pi_private, uio->uio_resid,
		    flags & O_NONBLOCK, &pi->pi_curput,
		    &pi->pi_curres, &pi->pi_curopaq);
		if (error) {
			return error;
		}
	}

	origres = uio->uio_resid;
	error = uiomove(pi->pi_curput, pi->pi_curres, uio);
	moved = origres - uio->uio_resid;
	DPRINTF(("putter_fop_read (%p): moved %zu bytes from %p, error %d\n",
	    pi, moved, pi->pi_curput, error));

	KASSERT(pi->pi_curres >= moved, ("pi->pi_curres >= moved"));
	pi->pi_curres -= moved;
	pi->pi_curput += moved;

	if (pi->pi_curres == 0) {
		pi->pi_pop->pop_releaseout(pi->pi_private,
		    pi->pi_curopaq, error);
		pi->pi_curput = NULL;
	}

	return error;
}

static int
putter_fop_write(struct cdev *dev, struct uio *uio, int flags)
{
	struct putter_instance *pi = dev->si_drv1;
	struct putter_hdr pth;
	uint8_t *buf;
	size_t frsize;
	int error;

	DPRINTF(("putter_fop_write (%p): writing response, resid %zu\n",
	    pi->pi_private, uio->uio_resid));

	if (pi->pi_private == PUTTER_EMBRYO || pi->pi_private == PUTTER_DEAD) {
		printf("putter_fop_write: putter %d not inited\n", pi->pi_idx);
		return ENOENT;
	}

	error = uiomove(&pth, sizeof(struct putter_hdr), uio);
	if (error) {
		return error;
	}

	/* Sorry mate, the kernel doesn't buffer. */
	frsize = pth.pth_framelen - sizeof(struct putter_hdr);
	if (uio->uio_resid < frsize) {
		return EINVAL;
	}

	buf = malloc(frsize + sizeof(struct putter_hdr), M_PUTTER, M_WAITOK);
	memcpy(buf, &pth, sizeof(pth));
	error = uiomove(buf+sizeof(struct putter_hdr), frsize, uio);
	if (error == 0) {
		pi->pi_pop->pop_dispatch(pi->pi_private,
		    (struct putter_hdr *)buf);
	}
	free(buf, M_PUTTER);

	return error;
}

/*
 * Poll query interface.  The question is only if an event
 * can be read from us.
 */
#define PUTTERPOLL_EVSET (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)
static int
putter_fop_poll(struct cdev *dev, int events, struct thread *td)
{
	struct putter_instance *pi = dev->si_drv1;
	int revents;

	if (pi->pi_private == PUTTER_EMBRYO || pi->pi_private == PUTTER_DEAD) {
		printf("putter_fop_ioctl: putter %d not inited\n", pi->pi_idx);
		return ENOENT;
	}

	revents = events & (POLLOUT | POLLWRNORM | POLLWRBAND);
	if ((events & PUTTERPOLL_EVSET) == 0) {
		return revents;
	}

	/* check queue */
	if (pi->pi_pop->pop_waitcount(pi->pi_private))
		revents |= PUTTERPOLL_EVSET;
	else
		selrecord(curthread, &pi->pi_sel);

	return revents;
}

/*
 * device close = forced unmount.
 *
 * unmounting is a frightfully complex operation to avoid races
 */
static int
putter_fop_close(struct cdev *dev, int flag, int fmt, struct thread *td)
{
	struct putter_instance *pi = dev->si_drv1;

	DPRINTF(("putter_fop_close: device closed\n"));

 restart:
	mtx_lock(&pi_mtx);
	/*
	 * First check if the fs was never mounted.  In that case
	 * remove the instance from the list.  If mount is attempted later,
	 * it will simply fail.
	 */
	if (pi->pi_private == PUTTER_EMBRYO) {
		TAILQ_REMOVE(&putter_ilist, pi, pi_entries);
		mtx_unlock(&pi_mtx);

		DPRINTF(("putter_fop_close: data associated with dev %p was "
		    "embryonic\n", dev));

		goto out;
	}

	/*
	 * Next, analyze if unmount was called and the instance is dead.
	 * In this case we can just free the structure and go home, it
	 * was removed from the list by putter_rmprivate().
	 */
	if (pi->pi_private == PUTTER_DEAD) {
		mtx_unlock(&pi_mtx);

		DPRINTF(("putter_fop_close: putter associated with dev %p (%d) "
		    "dead, freeing\n", dev, pi->pi_idx));

		goto out;
	}

	/*
	 * So we have a reference.  Proceed to unwrap the file system.
	 */
	mtx_unlock(&pi_mtx);

	/* hmm?  suspicious locking? */
	while (pi->pi_pop->pop_close(pi->pi_private) == ERESTART)
		goto restart;

 out:
	/*
	 * Finally, release the instance information.  It was already
	 * removed from the list by putter_rmprivate() and we know it's
	 * dead, so no need to lock.
	 */

	knlist_destroy(&pi->pi_sel.si_note);
	free(pi, M_PUTTER);

	return (0);
}

static int
putter_fop_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flags,
    struct thread *td)
{

	/*
	 * work already done in sys_ioctl().  skip sanity checks to enable
	 * setting non-blocking fd without yet having mounted the fs
	 */
	if (cmd == FIONBIO)
		return 0;

	return EINVAL;
}

/* kqueue stuff */

static void
filt_putterdetach(struct knote *kn)
{
	struct putter_instance *pi = kn->kn_hook;

	mtx_lock(&pi_mtx);
	knlist_remove(&pi->pi_sel.si_note, kn, 1);
	mtx_unlock(&pi_mtx);
}

static int
filt_putter(struct knote *kn, long hint)
{
	struct putter_instance *pi = kn->kn_hook;
	int error, rv;

	mtx_assert(&pi_mtx, MA_OWNED);
	error = 0;
	if (pi->pi_private == PUTTER_EMBRYO || pi->pi_private == PUTTER_DEAD)
		error = 1;
	if (error) {
		return 0;
	}

	kn->kn_data = pi->pi_pop->pop_waitcount(pi->pi_private);
	rv = kn->kn_data != 0;
	return rv;
}

static struct filterops putter_filtops = {
	.f_isfd =	1,
	.f_attach =	NULL,
	.f_detach =	filt_putterdetach,
	.f_event =	filt_putter,
};

static int
filt_putter_seltrue(struct knote *kn, long hint)
{
        /*
         * We don't know how much data can be read/written,
         * but we know that it *can* be.  This is about as
         * good as select/poll does as well.
         */
        kn->kn_data = 0;
        return (1);
}

/*
 * This provides full kqfilter entry for device switch tables, which
 * has same effect as filter using filt_seltrue() as filter method.
 */
static void
filt_putter_seltruedetach(struct knote *kn)
{
        /* Nothing to do */
}

static struct filterops putter_seltrue_filtops = {
	.f_isfd =	1,
	.f_attach =	NULL,
	.f_detach =	filt_putter_seltruedetach,
	.f_event =	filt_putter_seltrue,
};


static int
putter_fop_kqfilter(struct cdev *dev, struct knote *kn)
{
	struct putter_instance *pi = dev->si_drv1;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &putter_filtops;
		kn->kn_hook = pi;

		mtx_lock(&pi_mtx);
		knlist_add(&pi->pi_sel.si_note, kn, 1);
		mtx_unlock(&pi_mtx);

		break;
	case EVFILT_WRITE:
		kn->kn_fop = &putter_seltrue_filtops;
		break;
	default:
		return EINVAL;
	}

	return 0;
}

static	d_open_t	puttercdopen;

/* dev */
struct cdevsw putter_cdevsw = {
	.d_version =	D_VERSION,
	.d_flags =	D_PSEUDO | D_NEEDMINOR,
	.d_open =	puttercdopen,
	.d_close =	putter_fop_close,
	.d_read =	putter_fop_read,
	.d_write =	putter_fop_write,
	.d_ioctl =	putter_fop_ioctl,
	.d_poll =	putter_fop_poll,
	.d_kqfilter =	putter_fop_kqfilter,
	.d_name =	DEVICE_NAME,
};

static int
puttercdopen(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	struct putter_instance *pi;
	int error;
	pid_t pid;

	pid = td->td_proc->p_pid;
	pi = dev->si_drv1;

	if (pi != NULL) {
		mtx_lock(&pi_mtx);
		error = (pi->pi_pid == pid ? 0 : EBUSY);
		mtx_unlock(&pi_mtx);
		return (error);
	}

	pi = malloc(sizeof(struct putter_instance), M_PUTTER, M_WAITOK | M_ZERO);
	dev->si_drv1 = pi;

	mtx_lock(&pi_mtx);
	pi->pi_pid = pid;
	pi->pi_idx = dev2unit(dev);
	pi->pi_private = PUTTER_EMBRYO;
	knlist_init_mtx(&pi->pi_sel.si_note, &pi_mtx);
	mtx_unlock(&pi_mtx);

	TAILQ_INSERT_TAIL(&putter_ilist, pi, pi_entries);

	DPRINTF(("puttercdopen: registered embryonic pmp for pid: %d\n",
	    pi->pi_pid));

	return (0);
}

/*
 * Set the private structure for the file descriptor.  This is
 * typically done immediately when the counterpart has knowledge
 * about the private structure's address and the file descriptor
 * (e.g. vfs mount routine).
 *
 * We only want to make sure that the caller had the right to open the
 * device, we don't so much care about which context it gets in case
 * the same process opened multiple (since they are equal at this point).
 */
struct putter_instance *
putter_attach(pid_t pid, int unit, void *ppriv, struct putter_ops *pop)
{
	struct putter_instance *pi = NULL;

	mtx_lock(&pi_mtx);
	TAILQ_FOREACH(pi, &putter_ilist, pi_entries) {
		if (pi->pi_pid == pid && pi->pi_private == PUTTER_EMBRYO) {
			pi->pi_private = ppriv;
			pi->pi_pop = pop;
			break;
		    }
	}
	mtx_unlock(&pi_mtx);

	DPRINTF(("putter_setprivate: pi at %p (%d/%d)\n", pi,
	    pi ? pi->pi_pid : 0, pi ? pi->pi_idx : 0));

	return pi;
}

/*
 * Remove fp <-> private mapping.
 */
void
putter_detach(struct putter_instance *pi)
{

	mtx_lock(&pi_mtx);
	TAILQ_REMOVE(&putter_ilist, pi, pi_entries);
	pi->pi_private = PUTTER_DEAD;
	mtx_unlock(&pi_mtx);

	DPRINTF(("putter_nukebypmp: nuked %p\n", pi));
}

void
putter_notify(struct putter_instance *pi)
{

	selwakeup(&pi->pi_sel);
	KNOTE_UNLOCKED(&pi->pi_sel.si_note, 0);
}

static void
putter_dev_clone(void *arg, struct ucred *cred, char *name, int namelen, struct cdev **dev)
{
	int unit;

	if (*dev != NULL)
		return;
	if (strcmp(name, DEVICE_NAME) == 0)
		unit = -1;
	else if (dev_stdclone(name, NULL, DEVICE_NAME, &unit) != 1)
		return;

	if (clone_create(&putter_dev_clones, &putter_cdevsw, &unit, dev, 0)) {
		*dev = make_dev(&putter_cdevsw, unit,
				UID_ROOT, GID_WHEEL, 0600, DEVICE_NAME "%d", unit);
		if (*dev != NULL) {
			dev_ref(*dev);
			(*dev)->si_flags |= SI_CHEAPCLONE;
		}
	}
}

static int
putter_modevent(module_t mod, int type, void *data)
{
	static eventhandler_tag clone_tag;

	switch(type) {
	case MOD_LOAD:
		mtx_init(&pi_mtx, "pi_mtx", NULL, MTX_DEF);
		clone_setup(&putter_dev_clones);
		clone_tag = EVENTHANDLER_REGISTER(dev_clone, putter_dev_clone, 0, 1000);
		if (clone_tag == NULL) {
			clone_cleanup(&putter_dev_clones);
			mtx_destroy(&pi_mtx);
			return (ENOMEM);
		}
		break;

	case MOD_UNLOAD:
		EVENTHANDLER_DEREGISTER(dev_clone, clone_tag);
		clone_cleanup(&putter_dev_clones);
		mtx_destroy(&pi_mtx);
		break;

	case MOD_SHUTDOWN:
		break;

	default:
		return (EOPNOTSUPP);
	}

	return (0);
}

DEV_MODULE(putter, putter_modevent, NULL);
MODULE_VERSION(putter, 1);

