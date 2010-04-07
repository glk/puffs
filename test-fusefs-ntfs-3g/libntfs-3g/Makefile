LIB=	ntfs-3g
SRCS=	attrib.c 	\
	attrlist.c 	\
	bitmap.c 	\
	bootsect.c 	\
	collate.c 	\
	compat.c 	\
	compress.c 	\
	debug.c 	\
	device.c 	\
	dir.c 		\
	index.c 	\
	inode.c 	\
	lcnalloc.c 	\
	logfile.c 	\
	logging.c 	\
	mft.c 		\
	misc.c 		\
	mst.c 		\
	runlist.c 	\
	security.c 	\
	unistr.c 	\
	volume.c	\
	unix_io.c

LDADD+= -lrefuse -lpuffs 

NO_MAN=

MOUNT=	/usr/src/sbin/mount
.PATH:  ${MOUNT}

CFLAGS+= -g -I${.CURDIR}/../../librefuse -I${.CURDIR}/../../libpuffs -I${.CURDIR}/../../puffs -I${.CURDIR}/../../putter -I${MOUNT}
LDFLAGS+= -L${.OBJDIR}/../../libpuffs -L${.OBJDIR}/../../librefuse

CFLAGS+= -DHAVE_CONFIG_H -I${.CURDIR} -I${.CURDIR}/.. -I${.CURDIR}/../include/ntfs-3g -fPIC -DPIC 
LDFLAGS+= -pthread -L/usr/local/lib

.include <bsd.lib.mk>
