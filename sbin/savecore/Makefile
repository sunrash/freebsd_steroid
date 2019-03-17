# $FreeBSD: releng/12.0/sbin/savecore/Makefile 341603 2018-12-05 19:16:12Z gjb $

PACKAGE=runtime
CONFS=	minfree
VAR_CRASH=	/var/crash
VAR_CRASH_MODE=	0750
CONFSDIR=	VAR_CRASH
PROG=	savecore
LIBADD=	z xo
MAN=	savecore.8

.include <bsd.prog.mk>
