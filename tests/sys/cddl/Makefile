# $FreeBSD: releng/12.0/tests/sys/cddl/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

TESTSDIR=	${TESTSBASE}/sys/cddl

TESTS_SUBDIRS+=	${_zfs}

.if ${MK_ZFS} != "no"
_zfs=	zfs
.endif

.include <bsd.test.mk>
