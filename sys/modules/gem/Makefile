# $FreeBSD: releng/12.0/sys/modules/gem/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/gem

KMOD=	if_gem
SRCS=	bus_if.h device_if.h if_gem.c if_gem_pci.c ${if_gem_sbus} miibus_if.h
SRCS+=	${ofw_bus_if} pci_if.h

.if ${MACHINE} == "sparc64"
if_gem_sbus=	if_gem_sbus.c
.endif

.if ${MACHINE_CPUARCH} == "powerpc" || ${MACHINE_CPUARCH} == "sparc64"
ofw_bus_if=	ofw_bus_if.h
.endif

.include <bsd.kmod.mk>
