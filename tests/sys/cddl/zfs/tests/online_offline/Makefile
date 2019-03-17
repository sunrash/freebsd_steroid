# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/online_offline/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/online_offline
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	online_offline_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	online_offline_001_pos.ksh
${PACKAGE}FILES+=	online_offline.cfg
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	online_offline_002_neg.ksh

.include <bsd.test.mk>
