# $Id: Makefile,v 1.7 2003/08/14 20:06:17 max Exp $
# $FreeBSD: releng/12.0/usr.sbin/bluetooth/hccontrol/Makefile 338155 2018-08-21 19:28:53Z brd $

CONFS=		bluetooth.device.conf
CONFSDIR=	/etc/defaults
PROG=		hccontrol
MAN=		hccontrol.8
SRCS=		send_recv.c link_policy.c link_control.c le.c\
		host_controller_baseband.c info.c status.c node.c hccontrol.c \
		util.c
WARNS?=		2

LIBADD=		bluetooth

.include <bsd.prog.mk>
