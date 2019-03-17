# $FreeBSD: releng/12.0/sys/modules/nvme/Makefile 325795 2017-11-14 05:05:21Z imp $

.PATH: ${SRCTOP}/sys/dev/nvme

KMOD = nvme

SRCS =	nvme.c			\
	nvme_ctrlr.c		\
	nvme_ctrlr_cmd.c	\
	nvme_ns.c		\
	nvme_ns_cmd.c		\
	nvme_qpair.c		\
	nvme_sim.c		\
	nvme_sysctl.c		\
	nvme_test.c		\
	nvme_util.c		\
				\
	bus_if.h		\
	device_if.h		\
	opt_cam.h		\
	opt_nvme.h		\
	pci_if.h

.include <bsd.kmod.mk>
