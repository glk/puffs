PROG=	pnullfs
SRCS=	pnullfs.c getmntopts.c
LDADD+= -lpuffs -lutil
DBG=-g -O0

WARNS=	2

NO_MAN=	1

MOUNT=	/usr/src/sbin/mount
.PATH:  ${MOUNT}

CFLAGS+= -g -I${.CURDIR}/../libpuffs -I${.CURDIR}/../puffs -I${.CURDIR}/../putter -I${MOUNT}
LDFLAGS+= -L${.OBJDIR}/../libpuffs

.include <bsd.prog.mk>
