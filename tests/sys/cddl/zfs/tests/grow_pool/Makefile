# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/grow_pool/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/grow_pool
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	grow_pool_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	grow_pool_001_pos.ksh
${PACKAGE}FILES+=	grow_pool.cfg
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	setup.ksh

.include <bsd.test.mk>
