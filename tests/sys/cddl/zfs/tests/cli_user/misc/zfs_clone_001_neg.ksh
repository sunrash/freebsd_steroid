#!/usr/local/bin/ksh93 -p
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

# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/cli_user/misc/zfs_clone_001_neg.ksh 329867 2018-02-23 16:31:00Z asomers $

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"@(#)zfs_clone_001_neg.ksh	1.1	07/10/09 SMI"
#

. $STF_SUITE/include/libtest.kshlib
. $STF_SUITE/tests/cli_user/cli_user.kshlib

################################################################################
#
# __stc_assertion_start
#
# ID: zfs_clone_001_neg
#
# DESCRIPTION:
#
# zfs clone returns an error when run as a user
#
# STRATEGY:
#
# 1. Verify that we're unable to clone snapshots as a user
#
#
# TESTABILITY: explicit
#
# TEST_AUTOMATION_LEVEL: automated
#
# CODING_STATUS: COMPLETED (2007-07-27)
#
# __stc_assertion_end
#
################################################################################

log_assert "zfs clone returns an error when run as a user"
log_mustnot run_unprivileged "$ZFS clone $TESTPOOL/$TESTFS@snap $TESTPOOL/$TESTFS.myclone"

# check to see that the above command really did nothing
if datasetexists $TESTPOOL/$TESTFS.myclone
then
	log_fail "Dataset $TESTPOOL/$TESTFS.myclone should not exist!"
fi
log_pass "zfs clone returns an error when run as a user"
