LIB=		refuse

.ifdef DEBUG
FUSE_OPT_DEBUG_FLAGS=	-g -DFUSE_OPT_DEBUG
.endif

MOUNT=  /usr/src/sbin/mount
.PATH:  ${MOUNT}

CFLAGS+=	-DMULTITHREADED_REFUSE
CFLAGS+=	${FUSE_OPT_DEBUG_FLAGS}
CFLAGS+=	-g -I${.CURDIR}/../libpuffs -I${.CURDIR}/../putter -I${.CURDIR}/../puffs -I${MOUNT}
SRCS=		refuse.c refuse_opt.c
MAN=		refuse.3
WARNS=		2
#SHLIB_MAJOR=	1

.include <bsd.lib.mk>
