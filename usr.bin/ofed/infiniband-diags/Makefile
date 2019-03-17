# $FreeBSD: releng/12.0/usr.bin/ofed/infiniband-diags/Makefile 336569 2018-07-20 23:52:11Z kib $

.include <src.opts.mk>

SUBDIR= \
	ibstat

.if ${MK_OFED_EXTRA} != "no"
SUBDIR+= \
	dump_fts \
	ibaddr \
	ibcacheedit \
	ibccconfig \
	ibccquery \
	iblinkinfo \
	ibmirror \
	ibnetdiscover \
	ibping \
	ibportstate \
	ibqueryerrors \
	ibroute \
	ibsysstat \
	ibtracert \
	perfquery \
	saquery \
	sminfo \
	smpdump \
	smpquery \
	vendstat
.endif

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>

