# $FreeBSD: releng/12.0/lib/libcasper/services/Makefile 325739 2017-11-12 08:34:25Z oshogbo $

.include <src.opts.mk>

SUBDIR=		cap_dns
SUBDIR+=	cap_grp
SUBDIR+=	cap_pwd
SUBDIR+=	cap_random
SUBDIR+=	cap_sysctl
SUBDIR+=	cap_syslog

SUBDIR.${MK_TESTS}+=	tests

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
