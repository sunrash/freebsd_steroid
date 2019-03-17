#!/usr/bin/env ksh93
script=$(realpath $0)
export STF_BIN=$(dirname ${script})
export STF_SUITE=$(dirname ${STF_BIN})

# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/bin/testenv.ksh 329867 2018-02-23 16:31:00Z asomers $

env ENV=${STF_SUITE}/include/testenv.kshlib ksh93 -E -l
