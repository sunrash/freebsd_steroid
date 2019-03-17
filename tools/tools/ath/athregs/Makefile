# $FreeBSD: releng/12.0/tools/tools/ath/athregs/Makefile 296154 2016-02-28 06:30:39Z adrian $

PROG=	athregs

CFLAGS+=	-I${.CURDIR}/../common/

.PATH.c: ${.CURDIR}/../common

SRCS=	dumpregs.c
SRCS+=	ctrl.c
SRCS+=	dumpregs_5210.c
SRCS+=	dumpregs_5211.c
SRCS+=	dumpregs_5212.c
SRCS+=	dumpregs_5416.c
SRCS+=	opt_ah.h

CLEANFILES+=	opt_ah.h

opt_ah.h:
	echo "#define AH_DEBUG 1" > opt_ah.h
	echo "#define AH_DEBUG_COUNTRY 1" >> opt_ah.h
	echo "#define AH_SUPPORT_AR5416 1" >> opt_ah.h

.include <../Makefile.inc>

.include <bsd.prog.mk>
