#	From: @(#)Makefile	8.1 (Berkeley) 6/8/93
# $FreeBSD: releng/12.0/share/doc/usd/19.memacros/Makefile 314652 2017-03-04 11:26:40Z ngie $

VOLUME=		usd/19.memacros
SRCS=		meintro.me-sed
MACROS=		-me
GROFFDIR=	${SRCTOP}/contrib/groff
SRCDIR=		${GROFFDIR}/doc

version=`cat ${GROFFDIR}/VERSION`
revision=`sed -e 's/^0$$//' -e 's/^[1-9].*$$/.&/' ${GROFFDIR}/REVISION`

meintro.me-sed: meintro.me
	sed -e "s;@VERSION@;$(version)$(revision);" ${.ALLSRC} > ${.TARGET}

CLEANFILES=	${SRCS}

.include <bsd.doc.mk>
