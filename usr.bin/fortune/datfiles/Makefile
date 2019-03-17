#	@(#)Makefile	8.2 (Berkeley) 4/19/94
# $FreeBSD: releng/12.0/usr.bin/fortune/datfiles/Makefile 325828 2017-11-14 21:18:30Z benno $

DB=	freebsd-tips

BLDS=	${DB:S/$/.dat/}
FILES=	${DB} ${BLDS}
CLEANFILES+=${BLDS}

FILESDIR=	${SHAREDIR}/games/fortune

.for f in ${DB}
$f.dat: $f
	PATH=$$PATH:/usr/bin:${FORTUNE_OBJ}/strfile \
	    strfile -Cs ${.ALLSRC} ${.TARGET}
.endfor

.include <bsd.prog.mk>
