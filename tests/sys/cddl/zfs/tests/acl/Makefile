# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/acl/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/acl
FILESDIR=${TESTSDIR}

${PACKAGE}FILES+=	acl.cfg
${PACKAGE}FILES+=	acl_common.kshlib
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	setup.ksh

TESTS_SUBDIRS+=	cifs
TESTS_SUBDIRS+=	trivial
TESTS_SUBDIRS+=	nontrivial

.include <bsd.test.mk>
