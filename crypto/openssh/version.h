/* $OpenBSD: version.h,v 1.82 2018/07/03 11:42:12 djm Exp $ */
/* $FreeBSD: releng/12.0/crypto/openssh/version.h 338810 2018-09-19 20:52:47Z emaste $ */

#define SSH_VERSION	"OpenSSH_7.8"

#define SSH_PORTABLE	"p1"
#define SSH_RELEASE	SSH_VERSION SSH_PORTABLE

#define SSH_VERSION_FREEBSD	"FreeBSD-20180909"

#ifdef WITH_OPENSSL
#define OPENSSL_VERSION_STRING	SSLeay_version(SSLEAY_VERSION)
#else
#define OPENSSL_VERSION_STRING	"without OpenSSL"
#endif
