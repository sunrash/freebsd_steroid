# $FreeBSD: releng/12.0/sys/modules/netgraph/atm/sscop/Makefile 314651 2017-03-04 10:10:17Z ngie $
#
# Author: Harti Brandt <harti@freebsd.org>

LIBBASE= ${SRCTOP}/sys/contrib/ngatm

.PATH: ${SRCTOP}/sys/netgraph/atm/sscop ${LIBBASE}/netnatm/saal

KMOD=	ng_sscop
SRCS= 	ng_sscop.c saal_sscop.c
CFLAGS+= -I${LIBBASE} # -DSSCOP_DEBUG

.include <bsd.kmod.mk>
