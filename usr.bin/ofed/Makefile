# $FreeBSD: releng/12.0/usr.bin/ofed/Makefile 336569 2018-07-20 23:52:11Z kib $

.include <src.opts.mk>

SUBDIR= \
	libibverbs \
	librdmacm \
	infiniband-diags

SUBDIR.${MK_OFED_EXTRA}+= opensm

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
