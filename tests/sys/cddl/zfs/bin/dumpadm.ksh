#! /usr/local/bin/ksh93 -p

# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/bin/dumpadm.ksh 329867 2018-02-23 16:31:00Z asomers $

if [ $# != 0 ]
then
	echo "ERROR option not supported"
	return 1
fi
grep dumpdev /etc/rc.conf
