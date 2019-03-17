# $FreeBSD: releng/12.0/sys/modules/random_fortuna/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:	${SRCTOP}/sys/dev/random

KMOD	= random_fortuna
SRCS	= randomdev.c hash.c fortuna.c
SRCS	+= opt_param.h bus_if.h device_if.h
SRCS	+= opt_ddb.h
CFLAGS	+= -DRANDOM_LOADABLE

.include <bsd.kmod.mk>
