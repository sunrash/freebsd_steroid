# $FreeBSD: releng/12.0/secure/lib/Makefile.inc 314658 2017-03-04 11:35:30Z ngie $

.include "../Makefile.inc"
.if exists(${.CURDIR:H:H:H}/lib/Makefile.inc)
.include "${.CURDIR:H:H:H}/lib/Makefile.inc"
.endif
