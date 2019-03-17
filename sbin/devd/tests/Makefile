# $FreeBSD: releng/12.0/sbin/devd/tests/Makefile 320166 2017-06-20 19:34:21Z asomers $

ATF_TESTS_C=	client_test
TEST_METADATA.client_test=	required_files="/var/run/devd.pid"
TEST_METADATA.client_test+=	required_programs="devd"
TEST_METADATA.client_test+=	required_user="root"
TEST_METADATA.client_test+=	timeout=15

WARNS?=	5

.include <bsd.test.mk>
