PROG=	mount_psshfs
SRCS=	psshfs.c fs.c node.c psbuf.c subr.c getmntopts.c
LDADD+= -lpuffs

MAN=	mount_psshfs.8

MOUNT=	/usr/src/sbin/mount
.PATH:  ${MOUNT}

CFLAGS+= -g -I${.CURDIR}/../libpuffs -I${.CURDIR}/../puffs -I${.CURDIR}/../putter -I${MOUNT}
LDFLAGS+= -L${.OBJDIR}/../libpuffs

.include <bsd.prog.mk>
