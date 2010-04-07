/**
 * unix_io.c - Unix style disk io functions. Originated from the Linux-NTFS project.
 *
 * Copyright (c) 2000-2006 Anton Altaparmakov
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_LINUX_FD_H
#include <linux/fd.h>
#endif

/*
 * The following build definitions are available:
 * USE_ALIGNED_IO	- All I/O is done by blocks.
 * USE_UBLIO		- Use the ublio user space cache library.
 * USE_LOCK		- Lock the device/file when mounted.
 */

#ifdef __FreeBSD__
#include <sys/disk.h>
#define USE_ALIGNED_IO	1
#endif

#if USE_UBLIO
#include <sys/uio.h>
#endif

#include "types.h"
#include "mst.h"
#include "debug.h"
#include "device.h"
#include "logging.h"
#include "misc.h"

#if USE_UBLIO
#define UBLIO_USE_API		1
#include "ublio.h"
#define UBLIO_DEFAULT_ENABLE	1
#define UBLIO_DEFAULT_BLOCKSIZE	262144
#define UBLIO_DEFAULT_ITEMS	64
#define UBLIO_DEFAULT_GRACE	32
#define UBLIO_DEFAULT_SYNC_IO	0
#endif

#if USE_ALIGNED_IO
#define RAW_IO_ALIGNED(dev, offset, count)			\
	(DEV_HANDLE(dev)->block_size == 0 ||			\
	 ((offset) % DEV_HANDLE(dev)->block_size == 0 &&	\
	  (count) % DEV_HANDLE(dev)->block_size == 0))
#define RAW_IO_ALIGN(dev, offset)				\
	((offset) / DEV_HANDLE(dev)->block_size * DEV_HANDLE(dev)->block_size)
#define RAW_IO_MAX_SIZE (128 * 1024 * 1024)
#endif

struct unix_filehandle {
	int fd;
#if USE_ALIGNED_IO
	s64 pos;
	s32 block_size;
	s64 media_size;
#endif
#if USE_UBLIO
	ublio_filehandle_t ublio_fh;
#endif
};

#define DEV_HANDLE(dev)	((struct unix_filehandle *)dev->d_private)
#define DEV_FD(dev)	(DEV_HANDLE(dev)->fd)

/* Define to nothing if not present on this system. */
#ifndef O_EXCL
#	define O_EXCL 0
#endif

#if USE_ALIGNED_IO
/**
 * Get block_size and media_size
 */
static int
raw_io_get_size(struct ntfs_device *dev)
{
	int bs;
	off_t ms;
	struct stat sb;

	if (fstat(DEV_FD(dev), &sb) < 0) {
		ntfs_log_perror("Failed to stat '%s'", dev->d_name);
		return -1;
	}

	if (S_ISREG(sb.st_mode)) {
		DEV_HANDLE(dev)->media_size = sb.st_size;
		ntfs_log_trace("%s: regular file (media_size %lld)\n",
		    dev->d_name, DEV_HANDLE(dev)->media_size);
		if (getenv("FORCE_ALIGNED_IO"))
			DEV_HANDLE(dev)->block_size = 512;
		return 0;
	}

	if (ioctl(DEV_FD(dev), DIOCGSECTORSIZE, &bs) < 0) {
		ntfs_log_perror("Failed to ioctl(DIOCGSECTORSIZE) '%s'",
		    dev->d_name);
		return -1;
	}
	DEV_HANDLE(dev)->block_size = bs;
	ntfs_log_trace("%s: block size %d\n", dev->d_name, bs);

	if (ioctl(DEV_FD(dev), DIOCGMEDIASIZE, &ms) < 0) {
		ntfs_log_perror("Failed to ioctl(DIOCGMEDIASIZE) '%s'",
		    dev->d_name);
		return -1;
	}
	DEV_HANDLE(dev)->media_size = ms;
	ntfs_log_trace("%s: media size %lld\n", dev->d_name, ms);
	return 0;
}
#endif

/**
 * ntfs_device_unix_io_open - Open a device and lock it exclusively
 * @dev:
 * @flags:
 *
 * Description...
 *
 * Returns:
 */
static int ntfs_device_unix_io_open(struct ntfs_device *dev, int flags)
{
#if USE_ALIGNED_IO
	size_t sectsize;
#endif
#if USE_LOCK
	struct flock flk;
#endif
	struct stat sbuf;
	struct unix_filehandle *ufh;
	int err = 0;
	int is_special = 0;
#if USE_UBLIO
	struct ublio_param up;
	int use_ublio = 0;
	char *xenv, *xgarbage;
#endif

	if (NDevOpen(dev)) {
		errno = EBUSY;
		return -1;
	}
	if (stat(dev->d_name, &sbuf)) {
		ntfs_log_perror("Failed to access '%s'", dev->d_name);
		return -1;
	}
	if (S_ISBLK(sbuf.st_mode) || S_ISCHR(sbuf.st_mode))
		is_special = 1;
	
	ufh = ntfs_malloc(sizeof(*ufh));
	if (!ufh)
		return -1;
	dev->d_private = ufh;
#if USE_ALIGNED_IO
	ufh->fd = -1;
	ufh->pos = 0;
	ufh->block_size = 0;
	ufh->media_size = 0;
#endif

	/*
	 * Open file for exclusive access if mounting r/w.
	 * Fuseblk takes care about block devices.
	 */ 
	if (!is_special && (flags & O_RDWR) == O_RDWR)
		flags |= O_EXCL;
	ufh->fd = open(dev->d_name, flags);
	if (ufh->fd == -1) {
		err = errno;
		goto err_out;
	}
	
	if ((flags & O_RDWR) != O_RDWR)
		NDevSetReadOnly(dev);
	
#if USE_UBLIO
	ufh->ublio_fh = NULL;
	if ((xenv = getenv("NTFS_USE_UBLIO")) &&
	    (xenv[0] == '0' || xenv[0] == '1') && xenv[1] == '\0')
		use_ublio = (xenv[0] == '1');
	else
		use_ublio = UBLIO_DEFAULT_ENABLE;
	if ((xenv = getenv("UBLIO_BLOCKSIZE")))
		up.up_blocksize = strtoul(xenv, &xgarbage, 10);
	if (!xenv || *xgarbage != '\0')
		up.up_blocksize = UBLIO_DEFAULT_BLOCKSIZE;
	if ((xenv = getenv("UBLIO_ITEMS")))
		up.up_items = strtoul(xenv, &xgarbage, 10);
	if (!xenv || *xgarbage != '\0')
		up.up_items = UBLIO_DEFAULT_ITEMS;
	if ((xenv = getenv("UBLIO_GRACE")))
		up.up_grace = strtoul(xenv, &xgarbage, 10);
	if (!xenv || *xgarbage != '\0')
		up.up_grace = UBLIO_DEFAULT_GRACE;
	if ((xenv = getenv("UBLIO_SYNC_IO")) &&
	    (xenv[0] == '0' || xenv[0] == '1') && xenv[1] == '\0')
		up.up_sync_io = (xenv[0] == '1');
	else
		up.up_sync_io = UBLIO_DEFAULT_SYNC_IO;
	up.up_priv	= &ufh->fd;
	up.up_pread	= NULL;
	up.up_preadv	= NULL;
	up.up_pwrite	= NULL;
	up.up_pwritev	= NULL;
#endif
#if USE_LOCK
	memset(&flk, 0, sizeof(flk));
	if (NDevReadOnly(dev))
		flk.l_type = F_RDLCK;
	else
		flk.l_type = F_WRLCK;
	flk.l_whence = SEEK_SET;
	flk.l_start = flk.l_len = 0LL;
#endif
#if USE_ALIGNED_IO
	if (raw_io_get_size(dev) < 0) {
		err = errno;
		close(DEV_FD(dev));
		goto err_out;
	}
	if (S_ISBLK(sbuf.st_mode) || S_ISCHR(sbuf.st_mode))
		NDevSetBlock(dev);
#else
	if (S_ISBLK(sbuf.st_mode))
		NDevSetBlock(dev);
#endif /* USE_ALIGNED_IO */
#if USE_LOCK
	if (!NDevBlock(dev) && fcntl(DEV_FD(dev), F_SETLK, &flk)) {
		err = errno;
		ntfs_log_perror("Failed to %s lock '%s'", NDevReadOnly(dev) ? 
				"read" : "write", dev->d_name);
		if (close(DEV_FD(dev)))
			ntfs_log_perror("Failed to close '%s'", dev->d_name);
		goto err_out;
	}
#endif
#if USE_UBLIO
	if (use_ublio) {
		ufh->ublio_fh = ublio_open(&up);
		if (!ufh->ublio_fh) {
			close(DEV_FD(dev));
			goto err_out;
		}
	}
#endif
	NDevSetOpen(dev);
	return 0;
err_out:
	free(dev->d_private);
	dev->d_private = NULL;
	errno = err;
	return -1;
}

/**
 * ntfs_device_unix_io_close - Close the device, releasing the lock
 * @dev:
 *
 * Description...
 *
 * Returns:
 */
static int ntfs_device_unix_io_close(struct ntfs_device *dev)
{
	/* XXX no error if fysnc, fcntl (ublio_close) fails? */
#if USE_LOCK
	struct flock flk;
#endif

	if (!NDevOpen(dev)) {
		errno = EBADF;
		ntfs_log_perror("Device %s is not open", dev->d_name);
		return -1;
	}
	if (NDevDirty(dev))
		if (fsync(DEV_FD(dev))) {
			ntfs_log_perror("Failed to fsync device %s", dev->d_name);
			return -1;
		}

#if USE_LOCK
	memset(&flk, 0, sizeof(flk));
	flk.l_type = F_UNLCK;
	flk.l_whence = SEEK_SET;
	flk.l_start = flk.l_len = 0LL;
	if (!NDevBlock(dev) && fcntl(DEV_FD(dev), F_SETLK, &flk))
		ntfs_log_perror("Could not unlock %s", dev->d_name);
#endif
#if USE_UBLIO
	if (DEV_HANDLE(dev)->ublio_fh)
		ublio_close(DEV_HANDLE(dev)->ublio_fh);
#endif
	if (close(DEV_FD(dev))) {
		ntfs_log_perror("Failed to close device %s", dev->d_name);
		return -1;
	}
	NDevClearOpen(dev);
	free(dev->d_private);
	dev->d_private = NULL;
	return 0;
}

/**
 * ntfs_device_unix_io_seek - Seek to a place on the device
 * @dev:
 * @offset:
 * @whence:
 *
 * Description...
 *
 * Returns:
 */
static s64 ntfs_device_unix_io_seek(struct ntfs_device *dev, s64 offset,
		int whence)
{
#if USE_ALIGNED_IO
	s64 abs_pos;

	ntfs_log_trace("seek offset = 0x%llx, whence = %d.\n", offset, whence);
	switch (whence) {
	case SEEK_SET:
		abs_pos = offset;
		break;

	case SEEK_CUR:
		abs_pos = DEV_HANDLE(dev)->pos + offset;
		break;

	case SEEK_END:
		abs_pos = DEV_HANDLE(dev)->media_size + offset;
		break;

	default:
		ntfs_log_trace("Wrong mode %d.\n", whence);
		errno = EINVAL;
		return -1;
	}

	if (abs_pos < 0 || abs_pos > DEV_HANDLE(dev)->media_size) {
		ntfs_log_trace("Seeking outsize seekable area.\n");
		errno = EINVAL;
		return -1;
	}
	DEV_HANDLE(dev)->pos = abs_pos;
	return abs_pos;
#else
	return lseek(DEV_FD(dev), offset, whence);
#endif
}

#if USE_ALIGNED_IO

#if USE_UBLIO
#define pread_wrap(fd, buf, count, off)					\
	(DEV_HANDLE(fd)->ublio_fh ?					\
	ublio_pread(DEV_HANDLE(fd)->ublio_fh, buf, count, off) :	\
	pread(DEV_FD(fd), buf, count, off))
#define pwrite_wrap(fd, buf, count, off)				\
	(DEV_HANDLE(fd)->ublio_fh ?					\
	ublio_pwrite(DEV_HANDLE(fd)->ublio_fh, buf, count, off) :	\
	pwrite(DEV_FD(fd), buf, count, off))
#else
#define pread_wrap(fd, buf, count, off)		\
	pread(DEV_FD(fd), buf, count, off)
#define pwrite_wrap(fd, buf, count, off)	\
	pwrite(DEV_FD(fd), buf, count, off)
#endif

/**
 * aligned_pread - Perform an aligned positioned read from the device
 */
static s64 aligned_pread(struct ntfs_device *dev, void *buf, s64 count, s64 offset)
{
	s64 start, start_aligned;
	s64 end, end_aligned;
	size_t count_aligned;
	char *buf_aligned;
	ssize_t nr;

	/* short-circuit for regular files */
	start = offset;
	if (count > RAW_IO_MAX_SIZE)
		count = RAW_IO_MAX_SIZE;
	if (RAW_IO_ALIGNED(dev, start, count))
		return pread_wrap(dev, buf, count, start);

	/*
	 * +- start_aligned                 +- end_aligned
	 * |                                |
	 * |     +- start           +- end  |
	 * v     v                  v       v
	 * |----------|----------|----------|
	 *       ^                  ^
	 *       +----- count ------+
	 * ^                                ^
	 * +-------- count_aligned ---------+
	 */
	start_aligned = RAW_IO_ALIGN(dev, start);
	end = start + count;
	end_aligned = RAW_IO_ALIGN(dev, end) +
	    (RAW_IO_ALIGNED(dev, end, 0) ? 0 : DEV_HANDLE(dev)->block_size);
	count_aligned = end_aligned - start_aligned;
	ntfs_log_trace(
	    "%s: count = 0x%llx/0x%x, start = 0x%llx/0x%llx, end = 0x%llx/0x%llx\n",
	    dev->d_name, count, count_aligned,
	    start, start_aligned, end, end_aligned);

	/* allocate buffer */
	buf_aligned = ntfs_malloc(count_aligned);
	if (buf_aligned == NULL) {
		ntfs_log_trace("ntfs_malloc(%d) failed\n", count_aligned);
		return -1;
	}

	/* read aligned data */
	nr = pread_wrap(dev, buf_aligned, count_aligned, start_aligned);
	if (nr == 0)
		return 0;
	if (nr < 0 || nr < start - start_aligned) {
		free(buf_aligned);
		return -1;
	}

	/* copy out */
	memcpy(buf, buf_aligned + (start - start_aligned), count);
	free(buf_aligned);

	nr -= start - start_aligned;
	if (nr > count)
		nr = count;
	return nr;
}

/**
 * aligned_pwrite - Perform an aligned positioned write from the device
 */
static s64 aligned_pwrite(struct ntfs_device *dev, void *buf, s64 count, s64 offset)
{
	s64 start, start_aligned;
	s64 end, end_aligned;
	size_t count_aligned;
	char *buf_aligned;
	ssize_t nw;

	if (NDevReadOnly(dev)) {
		errno = EROFS;
		return -1;
	}
	NDevSetDirty(dev);

	/* short-circuit for regular files */
	start = offset;
	if (count > RAW_IO_MAX_SIZE)
		count = RAW_IO_MAX_SIZE;
	if (RAW_IO_ALIGNED(dev, start, count))
		return pwrite_wrap(dev, buf, count, start);

	/*
	 * +- start_aligned                 +- end_aligned
	 * |                                |
	 * |     +- start           +- end  |
	 * v     v                  v       v
	 * |----------|----------|----------|
	 *       ^                  ^
	 *       +----- count ------+
	 * ^                                ^
	 * +-------- count_aligned ---------+
	 */
	start_aligned = RAW_IO_ALIGN(dev, start);
	end = start + count;
	end_aligned = RAW_IO_ALIGN(dev, end) +
	    (RAW_IO_ALIGNED(dev, end, 0) ? 0 : DEV_HANDLE(dev)->block_size);
	count_aligned = end_aligned - start_aligned;
	ntfs_log_trace(
	    "%s: count = 0x%llx/0x%x, start = 0x%llx/0x%llx, end = 0x%llx/0x%llx\n",
	    dev->d_name, count, count_aligned,
	    start, start_aligned, end, end_aligned);

	/* allocate buffer */
	buf_aligned = ntfs_malloc(count_aligned);
	if (buf_aligned == NULL) {
		ntfs_log_trace("ntfs_malloc(%d) failed\n", count_aligned);
		return -1;
	}

	/* read aligned lead-in */
	if (pread_wrap(dev, buf_aligned, DEV_HANDLE(dev)->block_size, start_aligned) != DEV_HANDLE(dev)->block_size) {
		ntfs_log_trace("read lead-in failed\n");
		free(buf_aligned);
		return -1;
	}

	/* read aligned lead-out */
	if (end != end_aligned && count_aligned > DEV_HANDLE(dev)->block_size) {
		if (pread_wrap(dev, buf_aligned + count_aligned - DEV_HANDLE(dev)->block_size, DEV_HANDLE(dev)->block_size, end_aligned - DEV_HANDLE(dev)->block_size) != DEV_HANDLE(dev)->block_size) {
			ntfs_log_trace("read lead-out failed\n");
			free(buf_aligned);
			return -1;
		}
	}

	/* copy data to write */
	memcpy(buf_aligned + (start - start_aligned), buf, count);

	/* write aligned data */
	nw = pwrite_wrap(dev, buf_aligned, count_aligned, start_aligned);
	free(buf_aligned);
	if (nw < 0 || nw < start - start_aligned)
		return -1;

	nw -= start - start_aligned;
	if (nw > count)
		nw = count;
	return nw;
}

/**
 * aligned_read - Perform an aligned read from the device
 */
static s64 aligned_read(struct ntfs_device *dev, void *buf, s64 count)
{
	s64 nr = aligned_pread(dev, buf, count, DEV_HANDLE(dev)->pos);
	if (nr > 0)
		DEV_HANDLE(dev)->pos += nr;
	return nr;
}

/**
 * aligned_write - Perform an aligned read from the device
 */
static s64 aligned_write(struct ntfs_device *dev, void *buf, s64 count)
{
	s64 nw = aligned_pwrite(dev, buf, count, DEV_HANDLE(dev)->pos);
	if (nw > 0)
		DEV_HANDLE(dev)->pos += nw;
	return nw;
}

#undef ublio_pwrite
#undef ublio_pread

#endif

/**
 * ntfs_device_unix_io_read - Read from the device, from the current location
 * @dev:
 * @buf:
 * @count:
 *
 * Description...
 *
 * Returns:
 */
static s64 ntfs_device_unix_io_read(struct ntfs_device *dev, void *buf,
		s64 count)
{
#if USE_ALIGNED_IO
	return aligned_read(dev, buf, count);
#elif USE_UBLIO
	if (DEV_HANDLE(dev)->ublio_fh) {
		off_t offset;
		ssize_t res;

		offset = lseek(DEV_FD(dev), 0, SEEK_CUR);
		if (offset == -1)
			return -1;

		res = ublio_pread(DEV_HANDLE(dev)->ublio_fh, buf, count,
		    offset);
		if (res == -1)
			return -1;

		if (lseek(DEV_FD(dev), res, SEEK_CUR) == -1)
			return -1;

		return res;
	}
#endif

	return read(DEV_FD(dev), buf, count);
}

/**
 * ntfs_device_unix_io_write - Write to the device, at the current location
 * @dev:
 * @buf:
 * @count:
 *
 * Description...
 *
 * Returns:
 */
static s64 ntfs_device_unix_io_write(struct ntfs_device *dev, const void *buf,
		s64 count)
{
	if (NDevReadOnly(dev)) {
		errno = EROFS;
		return -1;
	}
	NDevSetDirty(dev);
#if USE_ALIGNED_IO
	return aligned_write(dev, buf, count);
#elif USE_UBLIO
	if (DEV_HANDLE(dev)->ublio_fh)
		off_t offset;
		ssize_t res;

		offset = lseek(DEV_FD(dev), 0, SEEK_CUR);
		if (offset == -1)
			return -1;

		res = ublio_pwrite(DEV_HANDLE(dev)->ublio_fh, (void *)buf,
		    count, offset);
		if (res == -1)
			return -1;

		if (lseek(DEV_FD(dev), res, SEEK_CUR) == -1)
			return -1;

		return res;
	}
#endif
	return write(DEV_FD(dev), buf, count);
}

/**
 * ntfs_device_unix_io_pread - Perform a positioned read from the device
 * @dev:
 * @buf:
 * @count:
 * @offset:
 *
 * Description...
 *
 * Returns:
 */
static s64 ntfs_device_unix_io_pread(struct ntfs_device *dev, void *buf,
		s64 count, s64 offset)
{
#if USE_ALIGNED_IO
	return aligned_pread(dev, buf, count, offset);
#elif USE_UBLIO
	if (DEV_HANDLE(dev)->ublio_fh)
		return ublio_pread(DEV_HANDLE(dev)->ublio_fh, buf, count,
		    offset);
#endif
	return pread(DEV_FD(dev), buf, count, offset);
}

/**
 * ntfs_device_unix_io_pwrite - Perform a positioned write to the device
 * @dev:
 * @buf:
 * @count:
 * @offset:
 *
 * Description...
 *
 * Returns:
 */
static s64 ntfs_device_unix_io_pwrite(struct ntfs_device *dev, const void *buf,
		s64 count, s64 offset)
{
	if (NDevReadOnly(dev)) {
		errno = EROFS;
		return -1;
	}
	NDevSetDirty(dev);
#if USE_ALIGNED_IO
	return aligned_pwrite(dev, buf, count, offset);
#elif USE_UBLIO
	if (DEV_HANDLE(dev)->ublio_fh)
		return ublio_pwrite(DEV_HANDLE(dev)->ublio_fh, (void *)buf,
		    count, offset);
#endif
	return pwrite(DEV_FD(dev), buf, count, offset);
}

/**
 * ntfs_device_unix_io_sync - Flush any buffered changes to the device
 * @dev:
 *
 * Description...
 *
 * Returns:
 */
static int ntfs_device_unix_io_sync(struct ntfs_device *dev)
{
	int res = 0;
	
	if (!NDevReadOnly(dev)) {
#if USE_UBLIO
		if (DEV_HANDLE(dev)->ublio_fh)
 			res = ublio_fsync(DEV_HANDLE(dev)->ublio_fh);
		if (!DEV_HANDLE(dev)->ublio_fh || !res)
			res = fsync(DEV_FD(dev));
#else
		res = fsync(DEV_FD(dev));
#endif
		if (res)
			ntfs_log_perror("Failed to sync device %s", dev->d_name);
		else
			NDevClearDirty(dev);
	}
	return res;
}

/**
 * ntfs_device_unix_io_stat - Get information about the device
 * @dev:
 * @buf:
 *
 * Description...
 *
 * Returns:
 */
static int ntfs_device_unix_io_stat(struct ntfs_device *dev, struct stat *buf)
{
	return fstat(DEV_FD(dev), buf);
}

/**
 * ntfs_device_unix_io_ioctl - Perform an ioctl on the device
 * @dev:
 * @request:
 * @argp:
 *
 * Description...
 *
 * Returns:
 */
static int ntfs_device_unix_io_ioctl(struct ntfs_device *dev, int request,
		void *argp)
{
	return ioctl(DEV_FD(dev), request, argp);
}

/**
 * Device operations for working with unix style devices and files.
 */
struct ntfs_device_operations ntfs_device_unix_io_ops = {
	.open		= ntfs_device_unix_io_open,
	.close		= ntfs_device_unix_io_close,
	.seek		= ntfs_device_unix_io_seek,
	.read		= ntfs_device_unix_io_read,
	.write		= ntfs_device_unix_io_write,
	.pread		= ntfs_device_unix_io_pread,
	.pwrite		= ntfs_device_unix_io_pwrite,
	.sync		= ntfs_device_unix_io_sync,
	.stat		= ntfs_device_unix_io_stat,
	.ioctl		= ntfs_device_unix_io_ioctl,
};
