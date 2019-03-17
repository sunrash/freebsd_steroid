# $FreeBSD: releng/12.0/tests/sys/netipsec/tunnel/empty.sh 326497 2017-12-03 13:52:35Z kp $

. $(atf_get_srcdir)/utils.subr

atf_test_case "v4" "cleanup"
v4_head()
{
	atf_set descr 'IPSec inet4 tunnel using NULL encryption'
	atf_set require.user root
}

v4_body()
{
	# Can't use filename "null" for this script: PR 223564
	ist_test 4 null ""
}

v4_cleanup()
{
	ist_cleanup
}

atf_test_case "v6" "cleanup"
v6_head()
{
	atf_set descr 'IPSec inet6 tunnel using NULL encryption'
	atf_set require.user root
}

v6_body()
{
	ist_test 6 null ""
}

v6_cleanup()
{
	ist_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "v4"
	atf_add_test_case "v6"
}