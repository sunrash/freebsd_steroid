# $FreeBSD: releng/12.0/lib/libnv/tests/Makefile 335347 2018-06-18 22:57:32Z oshogbo $

ATF_TESTS_CXX=	\
	cnv_tests \
	dnv_tests \
	nv_array_tests \
	nv_tests \

TAP_TESTS_C+=	nvlist_add_test
TAP_TESTS_C+=	nvlist_append_test
TAP_TESTS_C+=	nvlist_exists_test
TAP_TESTS_C+=	nvlist_free_test
TAP_TESTS_C+=	nvlist_get_test
TAP_TESTS_C+=	nvlist_move_test
TAP_TESTS_C+=	nvlist_send_recv_test

LIBADD+=	nv

WARNS?=		3

.include <bsd.test.mk>
