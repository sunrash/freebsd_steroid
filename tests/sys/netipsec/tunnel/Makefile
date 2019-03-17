# $FreeBSD: releng/12.0/tests/sys/netipsec/tunnel/Makefile 326497 2017-12-03 13:52:35Z kp $

PACKAGE=	tests

TESTSDIR=       ${TESTSBASE}/sys/netipsec/tunnel

ATF_TESTS_SH+=	empty \
		aes_cbc_128_hmac_sha1 \
		aes_cbc_256_hmac_sha2_256 \
		aes_gcm_128 \
		aes_gcm_256 \
		aesni_aes_cbc_128_hmac_sha1 \
		aesni_aes_cbc_256_hmac_sha2_256 \
		aesni_aes_gcm_128 \
		aesni_aes_gcm_256

${PACKAGE}FILES+=	utils.subr

.include <bsd.test.mk>
