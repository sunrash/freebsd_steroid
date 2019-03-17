# $FreeBSD: releng/12.0/usr.sbin/fstyp/Makefile 337160 2018-08-02 18:55:55Z mav $

.include <src.opts.mk>

PROG=	fstyp
SRCS=	cd9660.c exfat.c ext2fs.c fstyp.c geli.c msdosfs.c ntfs.c ufs.c

.if ${MK_ZFS} != "no"
SRCS +=	zfs.c
.endif

MAN=	fstyp.8

WARNS?=	2

.include <bsd.endian.mk>

.if ${TARGET_ENDIANNESS} == 1234
HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
.endif

.if ${MK_ZFS} != "no"
IGNORE_PRAGMA=  YES

CFLAGS+= -DNEED_SOLARIS_BOOLEAN -DHAVE_ZFS
CFLAGS+= -I${SRCTOP}/sys/cddl/compat/opensolaris
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/lib/libumem
CFLAGS+= -I${SRCTOP}/cddl/contrib/opensolaris/lib/libnvpair
CFLAGS+= -I${SRCTOP}/cddl/contrib/opensolaris/lib/libzpool/common
CFLAGS+= -I${SRCTOP}/sys/cddl/contrib/opensolaris/uts/common/fs/zfs
CFLAGS+= -I${SRCTOP}/sys/cddl/contrib/opensolaris/uts/common
CFLAGS+= -I${SRCTOP}/cddl/contrib/opensolaris/head
.endif

CFLAGS+=-I${SRCTOP}/sys

LIBADD=	geom md ufs

.if ${MK_ZFS} != "no"
LIBADD+=nvpair zfs
.endif

.include <bsd.prog.mk>
