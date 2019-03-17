# $FreeBSD: releng/12.0/sys/modules/sgx/Makefile 332122 2018-04-06 17:35:35Z brooks $

.PATH: ${SRCTOP}/sys/amd64/sgx

KMOD=	sgx
SRCS=	sgx.c sgxvar.h sgx_support.S
SRCS+=	opt_hwpmc_hooks.h opt_kstack_pages.h
DPSRCS=	assym.inc

sgx_support.o:  assym.inc
	${CC} -c -x assembler-with-cpp -DLOCORE ${CFLAGS} \
	    ${.IMPSRC} -o ${.TARGET}

.include <bsd.kmod.mk>
