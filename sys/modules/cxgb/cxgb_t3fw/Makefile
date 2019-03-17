# $FreeBSD: releng/12.0/sys/modules/cxgb/cxgb_t3fw/Makefile 314651 2017-03-04 10:10:17Z ngie $

CXGB = ${SRCTOP}/sys/dev/cxgb
.PATH: ${CXGB} 

KMOD= cxgb_t3fw
SRCS+= cxgb_t3fw.c
CFLAGS+= -g -I${CXGB}

.include <bsd.kmod.mk>
