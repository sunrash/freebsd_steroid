# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/redundancy/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/redundancy
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	redundancy_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	redundancy.cfg
${PACKAGE}FILES+=	redundancy_003_pos.ksh
${PACKAGE}FILES+=	redundancy_002_pos.ksh
${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	redundancy.kshlib
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	redundancy_001_pos.ksh
${PACKAGE}FILES+=	redundancy_004_neg.ksh

.include <bsd.test.mk>
