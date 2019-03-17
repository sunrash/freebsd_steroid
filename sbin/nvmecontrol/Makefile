# $FreeBSD: releng/12.0/sbin/nvmecontrol/Makefile 335091 2018-06-13 22:00:02Z imp $

PACKAGE=runtime
PROG=	nvmecontrol
SRCS=	nvmecontrol.c devlist.c firmware.c format.c identify.c identify_ext.c logpage.c \
	perftest.c reset.c ns.c nvme_util.c power.c nc_util.c wdc.c
MAN=	nvmecontrol.8

.PATH:	${SRCTOP}/sys/dev/nvme

.include <bsd.prog.mk>
