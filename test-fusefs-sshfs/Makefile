PROG=	sshfs
SRCS=	sshfs.c cache.c
LDADD+= -lrefuse -lpuffs 

NO_MAN=

MOUNT=	/usr/src/sbin/mount
.PATH:  ${MOUNT}

CFLAGS+= -g -I${.CURDIR}/../librefuse -I${.CURDIR}/../libpuffs -I${.CURDIR}/../puffs -I${.CURDIR}/../putter -I${MOUNT}
LDFLAGS+= -L${.OBJDIR}/../libpuffs -L${.OBJDIR}/../librefuse

CFLAGS+= -DHAVE_CONFIG_H -D_REENTRANT -DFUSE_USE_VERSION=26 -DLIBDIR=\"/usr/local/lib\"  -D_FILE_OFFSET_BITS=64 -D_REENTRANT -I/usr/local/include/glib-2.0 -I/usr/local/lib/glib-2.0/include -Wall -W -Icompat
LDFLAGS+= -pthread -L/usr/local/lib
LDADD+= -liconv -lgthread-2.0 -lglib-2.0


.include <bsd.prog.mk>
