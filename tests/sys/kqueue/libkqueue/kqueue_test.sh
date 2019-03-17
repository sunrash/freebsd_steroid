#!/bin/sh
# $FreeBSD: releng/12.0/tests/sys/kqueue/libkqueue/kqueue_test.sh 322214 2017-08-08 04:59:16Z ngie $

i=1
"$(dirname $0)/kqtest" | while read line; do
	echo $line | grep -q passed
	if [ $? -eq 0 ]; then
		echo "ok - $i $line"
		: $(( i += 1 ))
	fi

	echo $line | grep -q 'tests completed'
	if [ $? -eq 0 ]; then
		echo -n "1.."
		echo $line | cut -d' ' -f3
	fi
done
