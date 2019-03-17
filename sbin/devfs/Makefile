# $FreeBSD: releng/12.0/sbin/devfs/Makefile 338204 2018-08-22 15:55:23Z brd $

CONFS=	devfs.conf devfs.rules
CONFSDIR_devfs.rules=	/etc/defaults
CONFSMODE_devfs.rules=	600
PACKAGE=runtime
PROG=	devfs
SRCS=	devfs.c rule.c
MAN=	devfs.8

.include <bsd.prog.mk>
