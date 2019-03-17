# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/cli_root/zdb/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/cli_root/zdb
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	zdb_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	zdb_001_neg.ksh
${PACKAGE}FILES+=	zdb.cfg
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	setup.ksh

.include <bsd.test.mk>
