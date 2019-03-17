# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/link_count/Makefile 333495 2018-05-11 16:11:24Z emaste $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/link_count
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	link_count_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	link_count_001.ksh
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	link_count.cfg
${PACKAGE}FILES+=	setup.ksh

.include <bsd.test.mk>
