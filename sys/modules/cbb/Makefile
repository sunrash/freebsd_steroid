# $FreeBSD: releng/12.0/sys/modules/cbb/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/pccbb

KMOD=	cbb
SRCS=	pccbb.c pccbb_isa.c pccbb_pci.c \
	device_if.h bus_if.h power_if.h card_if.h isa_if.h pci_if.h pcib_if.h

.if ${MACHINE_ARCH} == "i386" || ${MACHINE_ARCH} == "amd64"
CFLAGS += -DNEW_PCIB
.endif

.include <bsd.kmod.mk>
