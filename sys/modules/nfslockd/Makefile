# $FreeBSD: releng/12.0/sys/modules/nfslockd/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/nlm ${SRCTOP}/sys/rpc
KMOD=	nfslockd
SRCS=	vnode_if.h \
	nlm_advlock.c \
	nlm_prot_clnt.c \
	nlm_prot_impl.c \
	nlm_prot_server.c \
	nlm_prot_svc.c \
	nlm_prot_xdr.c \
	sm_inter_xdr.c
SRCS+=	opt_inet6.h opt_nfs.h

.include <bsd.kmod.mk>
