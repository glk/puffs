# $FreeBSD$

.PATH: ${.CURDIR}/../../fs/puffs

KMOD=	puffs
SRCS=	vnode_if.h puffs_msgif.c puffs_msgif.h puffs_node.c puffs_subr.c \
	puffs_sys.h puffs_vfsops.c puffs_vnops.c
DEBUG_FLAGS+= -g -I${.CURDIR} -I${.CURDIR}/../putter
DEBUG_FLAGS+= -DPUFFSDEBUG

.include <bsd.kmod.mk>
