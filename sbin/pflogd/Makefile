# $FreeBSD: releng/12.0/sbin/pflogd/Makefile 314656 2017-03-04 11:33:01Z ngie $

.PATH:	${SRCTOP}/contrib/pf/pflogd

PACKAGE=pf
PROG=	pflogd
SRCS= 	pflogd.c pidfile.c privsep.c privsep_fdpass.c
MAN=	pflogd.8

CFLAGS+=-include ${SRCTOP}/lib/libpcap/config.h
CFLAGS+=-I${SRCTOP}/contrib/libpcap

LIBADD=	pcap

WARNS?=	2

.include <bsd.prog.mk>
