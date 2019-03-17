# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/zones/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/zones
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	zones_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	zones.cfg
${PACKAGE}FILES+=	zones_005_pos.ksh
${PACKAGE}FILES+=	zones_001_pos.ksh
${PACKAGE}FILES+=	zones_004_pos.ksh
${PACKAGE}FILES+=	zones_common.kshlib
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	zones_002_pos.ksh
${PACKAGE}FILES+=	zones_003_pos.ksh

.include <bsd.test.mk>
