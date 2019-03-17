# $Id: Makefile,v 1.7 2003/09/07 18:32:11 max Exp $
# $FreeBSD: releng/12.0/usr.sbin/bluetooth/rfcomm_pppd/Makefile 314659 2017-03-04 11:38:03Z ngie $

.PATH:	${SRCTOP}/usr.bin/bluetooth/rfcomm_sppd

PROG=		rfcomm_pppd
MAN=		rfcomm_pppd.8
SRCS=		rfcomm_pppd.c rfcomm_sdp.c
WARNS?=		2

LIBADD=		bluetooth sdp

.include <bsd.prog.mk>
