# $FreeBSD: releng/12.0/usr.sbin/periodic/etc/Makefile.inc 337648 2018-08-11 17:11:08Z brd $

CONFMODE=	755
CONFDIR=	ETC_PERIODIC_${.CURDIR:T:U}
ETC_PERIODIC_${.CURDIR:T:U}=	/etc/periodic/${.CURDIR:T}
NO_OBJ=
