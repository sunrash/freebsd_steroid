#!/bin/sh
# $FreeBSD: releng/12.0/tests/sys/geom/class/mirror/conf.sh 326863 2017-12-14 22:15:46Z markj $

name="$(mktemp -u mirror.XXXXXX)"
class="mirror"
base=`basename $0`

gmirror_test_cleanup()
{
	[ -c /dev/$class/$name ] && gmirror destroy $name
	geom_test_cleanup
}
trap gmirror_test_cleanup ABRT EXIT INT TERM

syncwait()
{
	while $(gmirror status -s $name | grep -q SYNCHRONIZING); do
		sleep 0.1;
	done
}

. `dirname $0`/../geom_subr.sh
