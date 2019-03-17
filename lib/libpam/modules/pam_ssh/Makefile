# PAM module for SSH
# $FreeBSD: releng/12.0/lib/libpam/modules/pam_ssh/Makefile 312452 2017-01-20 03:27:47Z ngie $

SSHDIR=	${SRCTOP}/crypto/openssh

LIB=	pam_ssh
MAN=	pam_ssh.8
SRCS=	pam_ssh.c
PACKAGE=	ssh

WARNS?=	5
CFLAGS+= -I${SSHDIR} -include ssh_namespace.h
SRCS+=	 ssh_namespace.h

LIBADD=	ssh

.include <bsd.lib.mk>

.PATH: ${SSHDIR}
