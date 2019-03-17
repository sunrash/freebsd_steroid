#
# $FreeBSD: releng/12.0/usr.sbin/pmc/Makefile 339064 2018-10-01 16:16:05Z br $
#

.include <src.opts.mk>
PROG_CXX=	pmc
MAN=	
WARNS?=	3
CXXFLAGS+= -O0 -std=c++14
CWARNFLAGS.gcc+= -Wno-redundant-decls

LIBADD=	kvm pmc m ncursesw pmcstat elf

SRCS=	pmc.c pmc_util.c cmd_pmc_stat.c \
	cmd_pmc_list.c cmd_pmc_filter.cc \
	cmd_pmc_summary.cc

.include <bsd.prog.mk>
