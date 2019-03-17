# $FreeBSD: releng/12.0/usr.sbin/wpa/hostapd_cli/Makefile 336203 2018-07-11 18:53:18Z cy $

.include "../Makefile.inc"

.PATH.c:${HOSTAPD_DISTDIR}

PROG=	hostapd_cli
SRCS=	cli.c common.c edit.c eloop.c hostapd_cli.c os_unix.c \
	wpa_ctrl.c wpa_debug.c

CFLAGS+= -DCONFIG_CTRL_IFACE
CFLAGS+= -DCONFIG_CTRL_IFACE_UNIX

LIBADD+=	util

MAN=	hostapd_cli.8

.include <bsd.prog.mk>
