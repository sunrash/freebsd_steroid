# $FreeBSD: releng/12.0/gnu/usr.bin/binutils/objdump/Makefile 325189 2017-10-31 00:07:37Z bdrewery $

.include "../Makefile.inc0"

.PATH: ${SRCDIR}/binutils ${SRCDIR}/binutils/doc

PROG=	objdump
SRCS=	objdump.c prdbg.c
CFLAGS+= -D_GNU_SOURCE
CFLAGS+= -I${.CURDIR}/${GNURELTOP}/libbinutils
CFLAGS+= -I${SRCDIR}/binutils
CFLAGS+= -DBFD_VERSION_STRING=\"${VERSION}\"
DPADD=	${GNURELTOP}/libbinutils/libbinutils.a
DPADD+=	${GNURELTOP}/libopcodes/libopcodes.a
DPADD+=	${GNURELTOP}/libbfd/libbfd.a
DPADD+=	${GNURELTOP}/libiberty/libiberty.a
LDADD=	${DPADD}

.include <bsd.prog.mk>
