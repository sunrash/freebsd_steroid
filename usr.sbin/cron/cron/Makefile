# $FreeBSD: releng/12.0/usr.sbin/cron/cron/Makefile 338497 2018-09-06 14:55:54Z brd $

CONFS=	crontab
PROG=	cron
MAN=	cron.8
SRCS=	cron.c database.c do_command.c job.c user.c popen.c

CFLAGS+= -DLOGIN_CAP -DPAM

LIBADD=	cron pam util

WARNS?=	2

.include <bsd.prog.mk>
