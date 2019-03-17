# $FreeBSD: releng/12.0/tools/tools/ath/ath_ee_9300_print/Makefile 264925 2014-04-25 19:25:05Z imp $

.PATH:	${.CURDIR}/../../../../sys/dev/ath/ath_hal

PROG=	ath_ee_9300_print
MAN=
SRCS=	main.c
SRCS+=	opt_ah.h
CLEANFILES+=	opt_ah.h

opt_ah.h:
	echo "#define AH_DEBUG 1" > opt_ah.h
	echo "#define AH_DEBUG_COUNTRY 1" >> opt_ah.h
	echo "#define AH_SUPPORT_AR5416 1" >> opt_ah.h

.include <../Makefile.inc>

.include <bsd.prog.mk>
