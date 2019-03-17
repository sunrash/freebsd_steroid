#!/usr/local/bin/ksh93 -p
#

# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/bin/zpool_bsd.ksh 331613 2018-03-27 11:49:15Z avg $

cmd=$1

if [[ -z $cmd ]]; then
	return 0
fi

shift


typeset option
case $cmd in
	create|add|attach|detach|replace|remove|online|offline|clear)
		for arg in $@; do
			if [[ $arg == "/dev/"* ]]; then
				arg=${arg#/dev/}
				arg="/dev/"$arg
			fi
			if [[ $arg == "/dev/"* ]]; then
				echo $arg | egrep "*s[0-9]$" > /dev/null 2>&1
				if [ $? -eq 0 ]
				then
					n=`echo $arg| wc -c`
					set -A map a b c d e f g h i j
					s=`echo $arg | cut -c $((n-1))`
					arg=${arg%s[0-9]}${map[$s]}
				fi
			fi

			option="${option} $arg"
		done
		;;
	*)
		option="$@"
		;;
esac

echo $cmd $option
