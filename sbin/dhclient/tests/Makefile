# $FreeBSD: releng/12.0/sbin/dhclient/tests/Makefile 314656 2017-03-04 11:33:01Z ngie $

.PATH:	${.CURDIR:H}

PLAIN_TESTS_C=				option-domain-search_test
SRCS.option-domain-search_test=		alloc.c convert.c hash.c options.c \
					tables.c fake.c option-domain-search.c
CFLAGS.option-domain-search_test+=	-I${.CURDIR:H}
LIBADD.option-domain-search_test=	util

WARNS?=	2

.include <bsd.test.mk>
