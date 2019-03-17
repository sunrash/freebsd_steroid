#
# $FreeBSD: releng/12.0/usr.sbin/praudit/Makefile 335290 2018-06-17 17:31:16Z asomers $
#

OPENBSMDIR=${SRCTOP}/contrib/openbsm
.PATH: ${OPENBSMDIR}/bin/praudit

CFLAGS+=	-I${OPENBSMDIR}

PROG=	praudit
MAN=	praudit.1

WARNS?=	3

LIBADD=	bsm

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
