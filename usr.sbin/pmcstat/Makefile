#
# $FreeBSD: releng/12.0/usr.sbin/pmcstat/Makefile 334749 2018-06-07 02:03:22Z mmacy $
#

PROG_CXX=	pmcstat
MAN=	pmcstat.8

LIBADD=	kvm pmc m ncursesw pmcstat elf

SRCS=	pmcstat.c pmcstat.h pmcstat_log.c \
pmcpl_callgraph.c pmcpl_gprof.c pmcpl_annotate.c \
pmcpl_annotate_cg.c pmcpl_calltree.c

.include <bsd.prog.mk>
