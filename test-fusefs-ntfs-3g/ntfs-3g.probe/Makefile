PROG=	ntfs-3g.probe

LDADD+= -lrefuse -lpuffs -lntfs-3g

NO_MAN=

MOUNT=	/usr/src/sbin/mount
.PATH:  ${MOUNT}

CFLAGS+= -g -I${.CURDIR}/../../librefuse -I${.CURDIR}/../../libpuffs -I${.CURDIR}/../../puffs -I${.CURDIR}/../../putter -I${MOUNT}
LDFLAGS+= -L${.OBJDIR}/../../libpuffs -L${.OBJDIR}/../../librefuse

CFLAGS+= -DHAVE_CONFIG_H -I${.CURDIR} -I${.CURDIR}/.. -I${.CURDIR}/../include/ntfs-3g 
LDFLAGS+= -L${.OBJDIR}/../libntfs-3g
LDFLAGS+= -pthread -L/usr/local/lib

.include <bsd.prog.mk>
