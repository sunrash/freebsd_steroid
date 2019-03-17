# $FreeBSD: releng/12.0/usr.sbin/eeprom/Makefile 314659 2017-03-04 11:38:03Z ngie $

.PATH: ${.CURDIR:H}/ofwdump

PROG=	eeprom
MAN=	eeprom.8
MANSUBDIR= /sparc64
SRCS=	eeprom.c ofw_options.c ofw_util.c
CFLAGS+= -I${.CURDIR:H}/ofwdump

.include <bsd.prog.mk>
