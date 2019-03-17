# $FreeBSD: releng/12.0/sys/modules/netgraph/netflow/Makefile 314651 2017-03-04 10:10:17Z ngie $
#
# Author: Gleb Smirnoff <glebius@freebsd.org>
#

.PATH: ${SRCTOP}/sys/netgraph/netflow

KMOD=   ng_netflow
SRCS=   ng_netflow.c netflow.c netflow_v9.c opt_inet6.h opt_route.h

.include <bsd.kmod.mk>
