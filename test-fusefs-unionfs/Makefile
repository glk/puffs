PROG=	unionfs
SRCS=	hashtable.c hashtable_itr.c hash.c elfhash.c unionfs.c \
	stats.c opts.c debug.c findbranch.c readdir.c general.c \
	unlink.c rmdir.c cow.c cow_utils.c string.c
LDADD+= -lrefuse -lpuffs 

NO_MAN=

MOUNT=	/usr/src/sbin/mount
.PATH:  ${MOUNT}

CFLAGS+= -g -I${.CURDIR}/../librefuse -I${.CURDIR}/../libpuffs -I${.CURDIR}/../puffs -I${.CURDIR}/../putter -I${MOUNT}
LDFLAGS+= -L${.OBJDIR}/../libpuffs -L${.OBJDIR}/../librefuse

CFLAGS += -Wall -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=26 -U_POSIX_SYNCHRONIZED_IO
LDFLAGS+= -pthread -lm

.include <bsd.prog.mk>

