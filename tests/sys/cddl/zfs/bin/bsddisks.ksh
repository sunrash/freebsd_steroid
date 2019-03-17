#!/usr/local/bin/ksh93

# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/bin/bsddisks.ksh 329867 2018-02-23 16:31:00Z asomers $

BSDDEVS="ad|da|mlxd|myld|aacd|ided|twed"
ls /dev|egrep "^($BSDDEVS)[0-9]+\$" |sed 's/^/\/dev\//'
