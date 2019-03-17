# $FreeBSD: releng/12.0/usr.sbin/ntp/doc/hints/Makefile 314472 2017-03-01 04:54:06Z ngie $

.include <src.opts.mk>

FILESDIR=	${SHAREDIR}/doc/ntp/hints

.if ${MK_HTML} != "no"
FILES=	a-ux aix bsdi changes decosf1 decosf2 freebsd hpux linux mpeix \
	notes-xntp-v3 parse refclocks rs6000 sco.html sgi \
	solaris-dosynctodr.html solaris.html solaris.xtra.4023118 \
	solaris.xtra.4095849 solaris.xtra.S99ntpd solaris.xtra.patchfreq \
	sun4 svr4-dell svr4_package todo vxworks.html winnt.html
.endif

.PATH: ${SRCTOP}/contrib/ntp/html/hints

.include <bsd.prog.mk>
