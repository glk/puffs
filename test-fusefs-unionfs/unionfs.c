/*
*
* This is offered under a BSD-style license. This means you can use the code for whatever you
* desire in any way you may want but you MUST NOT forget to give me appropriate credits when
* spreading your work which is based on mine. Something like "original implementation by Radek 
* Podgorny" should be fine.
*
* License: BSD-style license
* Copyright: Radek Podgorny <radek@podgorny.cz>,
*            Bernd Schubert <bernd-schubert@gmx.de>
*/

#ifdef linux
	// For pread()/pwrite()
	#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/statvfs.h>
#include <syslog.h>

#ifdef HAVE_SETXATTR
	#include <sys/xattr.h>
#endif

#include "unionfs.h"
#include "opts.h"
#include "stats.h"
#include "debug.h"
#include "findbranch.h"
#include "general.h"

#include "unlink.h"
#include "rmdir.h"
#include "readdir.h"
#include "cow.h"


static struct fuse_opt unionfs_opts[] = {
	FUSE_OPT_KEY("--help", KEY_HELP),
	FUSE_OPT_KEY("--version", KEY_VERSION),
	FUSE_OPT_KEY("-h", KEY_HELP),
	FUSE_OPT_KEY("-V", KEY_VERSION),
	FUSE_OPT_KEY("stats", KEY_STATS),
	FUSE_OPT_KEY("cow", KEY_COW),
	FUSE_OPT_KEY("noinitgroups", KEY_NOINITGROUPS),
	FUSE_OPT_END
};


static int unionfs_access(const char *path, int mask) {
	DBG("access\n");
	
	to_user();

	int i = find_rorw_root(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = access(p, mask);

	to_root();

	if (res == -1) return -errno;

	return 0;
}

static int unionfs_chmod(const char *path, mode_t mode) {
	DBG("chmod\n");

	to_user();

	int i = find_rw_root_cow(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = chmod(p, mode);

	to_root();

	if (res == -1) return -errno;

	return 0;
}

static int unionfs_chown(const char *path, uid_t uid, gid_t gid) {
	DBG("chown\n");

	to_user();

	int i = find_rw_root_cow(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = lchown(p, uid, gid);

	to_root();

	if (res == -1) return -errno;

	return 0;
}

/**
 * unionfs implementation of the create call
 * libfuse will call this to create regular files
 */
static int unionfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	DBG("create\n");

	to_user();

	int i = find_rw_root_cutlast(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = open(p, fi->flags, mode);

	to_root();

	if (res == -1) return -errno;

	fi->fh = res;
	remove_hidden(path, i);

	return 0;
}


// flush may be called multiple times for an open file, this must not really close the file. This is important if used on a network filesystem like NFS which flush the data/metadata on close()
static int unionfs_flush(const char *path, struct fuse_file_info *fi) {
	DBG("flush\n");

	if (uopt.stats_enabled && strcmp(path, STATS_FILENAME) == 0) return 0;

	to_user();

	int fd = dup(fi->fh);

	if (fd == -1) {
		// What to do now?
		if (fsync(fi->fh) == -1) {
			to_root();
			return -EIO;
		}

		to_root();
		return -errno;
	}

	int res = close(fd);

	to_root();

	if (res == -1) return -errno;

	return 0;
}

// Just a stub. This method is optional and can safely be left unimplemented
static int unionfs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
	DBG("fsync\n");

	if (uopt.stats_enabled && strcmp(path, STATS_FILENAME) == 0) return 0;

	to_user();

	int res;
	if (isdatasync) {
		res = fsync(fi->fh);
	} else {
		res = fsync(fi->fh);
	}

	if (res == -1) {
		to_root();
		return -errno;
	}

	to_root();
	return 0;
}

static int unionfs_getattr(const char *path, struct stat *stbuf) {
	DBG("getattr\n");

	if (uopt.stats_enabled && strcmp(path, STATS_FILENAME) == 0) {
		memset(stbuf, 0, sizeof(stbuf));
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = STATS_SIZE;
		return 0;
	}

	to_user();

	int i = find_rorw_root(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = lstat(p, stbuf);

	to_root();

	if (res == -1) return -errno;

	/* This is a workaround for broken gnu find implementations. Actually, 
	 * n_links is not defined at all for directories by posix. However, it
	 * seems to be common for filesystems to set it to one if the actual value
	 * is unknown. Since nlink_t is unsigned and since these broken implementations
	 * always substract 2 (for . and ..) this will cause an underflow, setting
	 * it to max(nlink_t).
	 */
	if (S_ISDIR(stbuf->st_mode)) stbuf->st_nlink = 1;

	return 0;
}

static int unionfs_link(const char *from, const char *to) {
	DBG("link\n");
	
	to_user();

	// hardlinks do not work across different filesystems so we need a copy of from first
	int i = find_rw_root_cow(from);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char f[PATHLEN_MAX], t[PATHLEN_MAX];
	snprintf(f, PATHLEN_MAX, "%s%s", uopt.roots[i].path, from);
	snprintf(t, PATHLEN_MAX, "%s%s", uopt.roots[i].path, to);

	int res = link(f, t);

	to_root();

	if (res == -1) return -errno;

	remove_hidden(to, i); // remove hide file (if any)
	return 0;
}

/**
 * unionfs mkdir() implementation
 *
 * NOTE: Never delete whiteouts directories here, since this will just
 *       make already hidden sub-branches visible again.
 */
static int unionfs_mkdir(const char *path, mode_t mode) {
	DBG("mkdir\n");

	to_user();

	int i = find_rw_root_cutlast(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = mkdir(p, mode);

	to_root();

	if (res == -1) return -errno;

	return 0;
}

static int unionfs_mknod(const char *path, mode_t mode, dev_t rdev) {
	DBG("mknod\n");

	to_user();

	int i = find_rw_root_cutlast(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = -1;
	if ((mode & S_IFMT) == S_IFREG) {
		// under FreeBSD, only the super-user can create ordinary files using mknod
		// Actually this workaround should not be required any more
		// since we now have the unionfs_create() method
		// So can we remove it?
		
		syslog (LOG_INFO, "deprecated mknod workaround, tell the unionfs-fuse authors if you see this!\n");
		
		res = creat(p, mode ^ S_IFREG);
		if (res > 0) 
			if (close (res) == -1) syslog (LOG_WARNING, "Warning, cannot close file\n");
	} else {
		res = mknod(p, mode, rdev);
	}

	to_root();

	if (res == -1) return -errno;
	
	remove_hidden(path, i);

	return 0;
}

static int unionfs_open(const char *path, struct fuse_file_info *fi) {
	DBG("open\n");

	if (uopt.stats_enabled && strcmp(path, STATS_FILENAME) == 0) {
		if ((fi->flags & 3) == O_RDONLY) {
			// This makes exec() fail
			//fi->direct_io = 1;
			return 0;
		}
		return -EACCES;
	}

	to_user();

	int i;
	if (fi->flags & (O_WRONLY | O_RDWR)) {
		i = find_rw_root_cutlast(path);
	} else {
		i = find_rorw_root(path);
	}
	
	if (i == -1) {
		to_root();
		return -errno;
	}
	
	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int fd = open(p, fi->flags);
	if (fd == -1 && fi->flags == O_RDONLY) {
		// workround for for files having the x-bit, but no r-bit
		// nfs also handles it this way
		if (access(p, X_OK) == 0) {
			to_root();
			fd = open(p, fi->flags); // we need root rights here
			to_user();
		}
	} else if (fd == -1) {
		to_root();
		return -errno;
	}

	to_root();
	
	if (fi->flags & (O_WRONLY | O_RDWR)) {
		// There might have been a hide file, but since we successfully wrote to the real file, a hide file must not exist anymore
		remove_hidden(path, i);
	}

	// This makes exec() fail
	//fi->direct_io = 1;
	fi->fh = (unsigned long)fd;

	return 0;
}

static int unionfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	DBG("read\n");

	if (uopt.stats_enabled && strcmp(path, STATS_FILENAME) == 0) {
		char out[STATS_SIZE] = "";
		stats_sprint(out);

		int s = size;
		if (offset < strlen(out)) {
			if (s > strlen(out)-offset) s = strlen(out)-offset;
			memcpy(buf, out+offset, s);
		} else {
			s = 0;
		}

		return s;
	}

	to_user();

	int res = pread(fi->fh, buf, size, offset);

	to_root();

	if (res == -1) return -errno;

	if (uopt.stats_enabled) stats_add_read(size);

	return res;
}


static int unionfs_readlink(const char *path, char *buf, size_t size) {
	DBG("readlink\n");

	to_user();

	int i = find_rorw_root(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = readlink(p, buf, size - 1);

	to_root();

	if (res == -1) return -errno;

	buf[res] = '\0';

	return 0;
}

static int unionfs_release(const char *path, struct fuse_file_info *fi) {
	DBG("release\n");

	if (uopt.stats_enabled && strcmp(path, STATS_FILENAME) == 0) return 0;

	to_user();

	int res = close(fi->fh);

	to_root();

	if (res == -1) return -errno;

	return 0;
}

/**
 * unionfs rename function
 * TODO: If we rename a directory on a read-only branch, we need to copy over 
 *       all files to the renamed directory on the read-write branch.
 */
static int unionfs_rename(const char *from, const char *to) {
	DBG("rename\n");
	
	bool is_dir = false; // is 'from' a file or directory

	to_user();

	int j = find_rw_root_cutlast(to);
	if (j == -1) {
		to_root();
		return -errno;
	}

	int i = find_rorw_root(from);
	if (i == -1) {
		to_root();
		return -errno;
	}

	if (!uopt.roots[i].rw) {
		i = find_rw_root_cow(from);
		if (i == -1) {
			to_root();
			return -errno;
		}
	}

	if (i != j) {
		to_root();
		syslog(LOG_ERR, "%s: from and to are on different writable branches %d vs %d, which"
		       "is not supported yet.\n", __func__, i, j);
		return -EXDEV;
	}

	char f[PATHLEN_MAX], t[PATHLEN_MAX];
	snprintf(f, PATHLEN_MAX, "%s%s", uopt.roots[i].path, from);
	snprintf(t, PATHLEN_MAX, "%s%s", uopt.roots[i].path, to);

	int res = path_is_dir(f);
	if (res == -1) {
		to_root();
		return -ENOENT;
	} else if (res == 1) is_dir = true;

	if (!uopt.roots[i].rw) {
		// since original file is on a read-only root, we copied the from file to a writable root,
		// but since we will rename from, we also need to hide the from file on the read-only root
		if (is_dir)
			res = hide_dir(from, i);
		else
			res = hide_file(from, i);
		if (res) {
			to_root();
			return -errno;
		}
	}

	res = rename(f, t);

	to_root();

	if (res == -1) {
		int err = errno; // unlink() might overwrite errno
		// if from was on a read-only branch we copied it, but now rename failed so we need to delete it
		if (!uopt.roots[i].rw) {
			if (unlink(f))
				syslog(LOG_ERR, "%s: cow of %s succeeded, but rename() failed and now "
				       "also unlink()  failed\n", __func__, from);
			
			if (remove_hidden(from, i))
				syslog(LOG_ERR, "%s: cow of %s succeeded, but rename() failed and now "
				       "also removing the whiteout  failed\n", __func__, from);
		}
		return -err;
	}

	if (uopt.roots[i].rw) {
		// A lower branch still *might* have a file called 'from', we need to delete this.
		// We only need to do this if we have been on a rw-branch, since we created
		// a whiteout for read-only branches anyway.
		if (is_dir)
			maybe_whiteout(from, i, WHITEOUT_DIR);
		else
			maybe_whiteout(from, i, WHITEOUT_FILE);
	}

	remove_hidden(to, i); // remove hide file (if any)
	return 0;
}

static int unionfs_statfs(const char *path, struct statvfs *stbuf) {
	(void)path;

	to_user();

	DBG("statfs\n");

	int first = 1;

	dev_t devno[uopt.nroots];

	int i = 0;
	for (i = 0; i < uopt.nroots; i++) {
		struct statvfs stb;
		int res = statvfs(uopt.roots[i].path, &stb);
		if (res == -1) continue;

		struct stat st;
		res = stat(uopt.roots[i].path, &st);
		if (res == -1) continue;
		devno[i] = st.st_dev;

		if (first) {
			memcpy(stbuf, &stb, sizeof(*stbuf));
			first = 0;
		} else {
			// Eliminate same devices
			int j = 0;
			for (j = 0; j < i; j ++) {
				if (st.st_dev == devno[j]) break;
			}

			if (j == i) {
				// Filesystem can have different block sizes -> normalize to first's block size
				double ratio = (double)stb.f_bsize / (double)stbuf->f_bsize;

				stbuf->f_blocks += stb.f_blocks * ratio;
				stbuf->f_bfree += stb.f_bfree * ratio;
				stbuf->f_bavail += stb.f_bavail * ratio;

				stbuf->f_files += stb.f_files;
				stbuf->f_ffree += stb.f_ffree;
				stbuf->f_favail += stb.f_favail;

				if (!stb.f_flag & ST_RDONLY) stbuf->f_flag &= ~ST_RDONLY;
				if (!stb.f_flag & ST_NOSUID) stbuf->f_flag &= ~ST_NOSUID;

				if (stb.f_namemax < stbuf->f_namemax) stbuf->f_namemax = stb.f_namemax;
			}
		}
	}

	stbuf->f_fsid = 0;

	to_root();
	return 0;
}

static int unionfs_symlink(const char *from, const char *to) {
	DBG("symlink\n");

	to_user();

	int i = find_rw_root_cutlast(to);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char t[PATHLEN_MAX];
	snprintf(t, PATHLEN_MAX, "%s%s", uopt.roots[i].path, to);

	int res = symlink(from, t);

	to_root();

	if (res == -1) return -errno;


	remove_hidden(to, i); // remove hide file (if any)
	return 0;
}

static int unionfs_truncate(const char *path, off_t size) {
	DBG("truncate\n");

	to_user();

	int i = find_rw_root_cow(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = truncate(p, size);

	to_root();

	if (res == -1) return -errno;

	return 0;
}

static int unionfs_utime(const char *path, struct utimbuf *buf) {
	DBG("utime\n");

	if (uopt.stats_enabled && strcmp(path, STATS_FILENAME) == 0) return 0;

	to_user();

	int i = find_rw_root_cow(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = utime(p, buf);

	to_root();

	if (res == -1) return -errno;

	return 0;
}

static int unionfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
	(void)path;

	DBG("write\n");

	to_user();

	int res = pwrite(fi->fh, buf, size, offset);

	to_root();

	if (res == -1) return -errno;

	if (uopt.stats_enabled) stats_add_written(size);

	return res;
}

#ifdef HAVE_SETXATTR
static int unionfs_getxattr(const char *path, const char *name, char *value, size_t size) {
	DBG("getxattr\n");

	to_user();

	int i = find_rorw_root(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = lgetxattr(p, name, value, size);

	to_root();

	if (res == -1) return -errno;

	return res;
}

static int unionfs_listxattr(const char *path, char *list, size_t size) {
	DBG("listxattr\n");

	to_user();

	int i = find_rorw_root(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = llistxattr(p, list, size);

	to_root();

	if (res == -1) return -errno;

	return res;
}

static int unionfs_removexattr(const char *path, const char *name) {
	DBG("removexattr\n");
	
	to_user();

	int i = find_rw_root_cow(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = lremovexattr(p, name);

	to_root();

	if (res == -1) return -errno;

	return res;
}

static int unionfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
	DBG("sexattr\n");

	to_user();

	int i = find_rw_root_cow(path);
	if (i == -1) {
		to_root();
		return -errno;
	}

	char p[PATHLEN_MAX];
	snprintf(p, PATHLEN_MAX, "%s%s", uopt.roots[i].path, path);

	int res = lsetxattr(p, name, value, size, flags);

	to_root();

	if (res == -1) return -errno;
	
	return res;
}
#endif // HAVE_SETXATTR

static struct fuse_operations unionfs_oper = {
	.access	= unionfs_access,
	.chmod	= unionfs_chmod,
	.chown	= unionfs_chown,
	.create = unionfs_create,
	.flush	= unionfs_flush,
	.fsync	= unionfs_fsync,
	.getattr	= unionfs_getattr,
	.link	= unionfs_link,
	.mkdir	= unionfs_mkdir,
	.mknod	= unionfs_mknod,
	.open	= unionfs_open,
	.read	= unionfs_read,
	.readlink	= unionfs_readlink,
	.readdir	= unionfs_readdir,
	.release	= unionfs_release,
	.rename	= unionfs_rename,
	.rmdir	= unionfs_rmdir,
	.statfs	= unionfs_statfs,
	.symlink	= unionfs_symlink,
	.truncate	= unionfs_truncate,
	.unlink	= unionfs_unlink,
	.utime	= unionfs_utime,
	.write	= unionfs_write,
#ifdef HAVE_SETXATTR
	.getxattr	= unionfs_getxattr,
	.listxattr	= unionfs_listxattr,
	.removexattr	= unionfs_removexattr,
	.setxattr	= unionfs_setxattr,
#endif
};

int main(int argc, char *argv[]) {
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	int res = debug_init();
	if (res != 0) return res;

	uopt_init();

	if (fuse_opt_parse(&args, NULL, unionfs_opts, unionfs_opt_proc) == -1) return 1;

	if (!uopt.doexit) {
		if (uopt.nroots == 0) {
			printf("You need to specify at least one root!\n");
			return 1;
		}

		if (uopt.stats_enabled) stats_init();
	}
	
	// This is only a temporarily workaround, which will go away soon!
	// Set single threading mode.
	if (fuse_opt_add_arg(&args, "-s")) {
		fprintf(stderr, "Adding the single-thread option failed, but we present MUST run single threaded, aborting\n");
		exit (1);
	}

	umask(0);
	res = fuse_main(args.argc, args.argv, &unionfs_oper, NULL);
	return uopt.doexit ? uopt.retval : res;
}
