# $FreeBSD: releng/12.0/secure/lib/Makefile 321912 2017-08-02 08:35:51Z ngie $

.include <src.opts.mk>

SUBDIR= 
.if ${MK_OPENSSL} != "no"
SUBDIR+=libcrypto libssl
.if ${MK_OPENSSH} != "no"
SUBDIR+=libssh
.endif
.endif

SUBDIR.${MK_TESTS}+= tests

.include <bsd.subdir.mk>
