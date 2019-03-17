# $FreeBSD: releng/12.0/sys/modules/nvdimm/Makefile 339416 2018-10-18 00:51:42Z bz $

.PATH: ${SRCTOP}/sys/dev/nvdimm

KMOD=	nvdimm
SRCS=	nvdimm.c \
	nvdimm_spa.c

SRCS+=	acpi_if.h bus_if.h device_if.h

.include <bsd.kmod.mk>
