# $FreeBSD: releng/12.0/sys/modules/netgraph/Makefile.inc 314651 2017-03-04 10:10:17Z ngie $
# $Whistle: Makefile.inc,v 1.4 1999/01/19 23:46:16 archie Exp $

.PATH:		${SRCTOP}/sys/netgraph

SRCS+=	opt_netgraph.h

.include "../Makefile.inc"
