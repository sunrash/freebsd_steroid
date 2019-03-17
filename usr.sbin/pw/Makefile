# $FreeBSD: releng/12.0/usr.sbin/pw/Makefile 322515 2017-08-14 19:21:37Z ngie $

PROG=	pw
MAN=	pw.conf.5 pw.8
SRCS=	pw.c pw_conf.c pw_user.c pw_group.c pw_log.c pw_nis.c pw_vpw.c \
	grupd.c pwupd.c psdate.c bitmap.c cpdir.c rm_r.c strtounum.c \
	pw_utils.c

WARNS?=	3

LIBADD=	crypt util sbuf

.include <src.opts.mk>

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
