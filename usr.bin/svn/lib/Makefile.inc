# $FreeBSD: releng/12.0/usr.bin/svn/lib/Makefile.inc 315170 2017-03-12 18:58:44Z imp $

.if !defined(SVNDIR)

SVNDIR=		${SRCTOP}/contrib/subversion/subversion
APRU=		${SRCTOP}/contrib/apr-util
APR=		${SRCTOP}/contrib/apr
SQLITE=		${SRCTOP}/contrib/sqlite3
SERF=		${SRCTOP}/contrib/serf

WARNS?=		0	# definitely not ready

.if exists(${.CURDIR}/../../../Makefile.inc)
.include "${.CURDIR}/../../../Makefile.inc"
.endif

.endif
