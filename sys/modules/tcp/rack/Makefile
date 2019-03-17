#
# $FreeBSD: releng/12.0/sys/modules/tcp/rack/Makefile 334815 2018-06-07 20:57:12Z rrs $
#

.PATH: ${.CURDIR}/../../../netinet/tcp_stacks

STACKNAME=	rack
KMOD=	tcp_${STACKNAME}
SRCS=	rack.c sack_filter.c

SRCS+=	opt_inet.h opt_inet6.h opt_ipsec.h
SRCS+=	opt_tcpdebug.h
SRCS+=	opt_kern_tls.h

#
# Enable full debugging
#
#CFLAGS += -g

CFLAGS+=	-DMODNAME=${KMOD}
CFLAGS+=	-DSTACKNAME=${STACKNAME}

.include <bsd.kmod.mk>
