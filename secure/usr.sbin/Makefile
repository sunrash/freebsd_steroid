# $FreeBSD: releng/12.0/secure/usr.sbin/Makefile 321912 2017-08-02 08:35:51Z ngie $

.include <src.opts.mk>

SUBDIR= 
.if ${MK_OPENSSH} != "no"
SUBDIR+=sshd
.endif

SUBDIR.${MK_TESTS}+= tests

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
