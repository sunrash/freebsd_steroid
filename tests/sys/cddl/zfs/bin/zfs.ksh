#! /usr/local/bin/ksh93 -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/bin/zfs.ksh 329867 2018-02-23 16:31:00Z asomers $

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"@(#)zfs.ksh	1.2	09/01/13 SMI"
#

ZFS=/sbin/zfs

set -A saved_options -- "$@"

for wrapper in ${ZFS_WRAPPER} ; do
	if [[ -x ${STF_SUITE}/bin/zfs_$wrapper ]]; then
		options=$(${STF_SUITE}/bin/zfs_$wrapper "${saved_options[@]}")
		set -A saved_options -- $options
	fi
done
	    
$ZFS "${saved_options[@]}"
return $?