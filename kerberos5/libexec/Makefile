# $FreeBSD: releng/12.0/kerberos5/libexec/Makefile 311114 2017-01-02 19:02:00Z ngie $

.include <src.opts.mk>

SUBDIR=	digest-service ipropd-master ipropd-slave hprop hpropd kdc \
	kdigest kfd kimpersonate kpasswdd kcm
SUBDIR_PARALLEL=

.if ${MK_GSSAPI} != "no"
SUBDIR+=	kadmind
.endif

.include <bsd.subdir.mk>
