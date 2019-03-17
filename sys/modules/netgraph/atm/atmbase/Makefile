# $FreeBSD: releng/12.0/sys/modules/netgraph/atm/atmbase/Makefile 314651 2017-03-04 10:10:17Z ngie $
#
# Author: Harti Brandt <harti@freebsd.org>
#

LIBBASE= ${SRCTOP}/sys/contrib/ngatm

.PATH: ${SRCTOP}/sys/netgraph/atm
.PATH: ${LIBBASE}/netnatm/misc
.PATH: ${LIBBASE}/netnatm/msg

KMOD=	ngatmbase
SRCS= 	ngatmbase.c unimsg_common.c straddr.c				\
	traffic.c uni_ie.c uni_msg.c

CFLAGS+= -I${LIBBASE} # -DNGATM_DEBUG

.include <bsd.kmod.mk>
