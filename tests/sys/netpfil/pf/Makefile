# $FreeBSD: releng/12.0/tests/sys/netpfil/pf/Makefile 337646 2018-08-11 16:41:07Z kp $

PACKAGE=	tests

TESTSDIR=       ${TESTSBASE}/sys/netpfil/pf
TESTS_SUBDIRS+=	ioctl

ATF_TESTS_SH+=	pass_block \
		forward \
		fragmentation \
		set_tos \
		route_to \
		synproxy \
		set_skip

${PACKAGE}FILES+=	utils.subr \
			echo_inetd.conf \
			pft_ping.py

${PACKAGE}FILESMODE_pft_ping.py=	0555

.include <bsd.test.mk>
