#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: releng/12.0/usr.bin/locate/locate/Makefile 338758 2018-09-18 20:50:07Z brd $

CONFS=	locate.rc
PROG=	locate
SRCS=	util.c locate.c
CFLAGS+= -I${.CURDIR} -DMMAP # -DDEBUG (print time) -O2 (10% faster)
SCRIPTS=updatedb.sh mklocatedb.sh concatdb.sh
MAN=	locate.1 locate.updatedb.8

WARNS?=	2

SCRIPTSDIR=	${LIBEXECDIR}
.for script in ${SCRIPTS}
SCRIPTSNAME_${script}=	locate.${script:R}
.endfor
MLINKS+= locate.updatedb.8 updatedb.8

.include "../../Makefile.inc"
.include <bsd.prog.mk>
