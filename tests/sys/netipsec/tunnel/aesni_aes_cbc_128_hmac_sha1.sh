# $FreeBSD: releng/12.0/tests/sys/netipsec/tunnel/aesni_aes_cbc_128_hmac_sha1.sh 326500 2017-12-03 18:35:07Z kp $

. $(atf_get_srcdir)/utils.subr

atf_test_case "v4" "cleanup"
v4_head()
{
	atf_set descr 'IPSec inet4 tunnel using aes-cbc-128-hmac-sha1 and AESNI'
	atf_set require.user root
}

v4_body()
{
	# load AESNI module if not already
	kldstat -q -n aesni || kldload aesni

	ist_test 4 rijndael-cbc "1234567890123456" hmac-sha1 "12345678901234567890"
}

v4_cleanup()
{
	ist_cleanup
}

atf_test_case "v6" "cleanup"
v6_head()
{
	atf_set descr 'IPSec inet6 tunnel using aes-cbc-128-hmac-sha1 and AESNI'
	atf_set require.user root
}

v6_body()
{
	# load AESNI module if not already
	kldstat -q -n aesni || kldload aesni

	ist_test 6 rijndael-cbc "1234567890123456" hmac-sha1 "12345678901234567890"
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
