# $FreeBSD: releng/12.0/usr.sbin/bsnmpd/gensnmptree/Makefile 314659 2017-03-04 11:38:03Z ngie $
#
# Author: Harti Brandt <harti@freebsd.org>

CONTRIB=${SRCTOP}/contrib/bsnmp
.PATH: ${CONTRIB}/gensnmptree

PROG=	gensnmptree
CFLAGS+= -I${CONTRIB}/lib
CFLAGS+= -DQUADFMT='"llu"' -DQUADXFMT='"llx"' -DHAVE_STDINT_H
CFLAGS+= -DHAVE_INTTYPES_H

WARNS?=	5

.include <bsd.prog.mk>
