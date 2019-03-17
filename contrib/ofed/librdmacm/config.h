/* $FreeBSD: releng/12.0/contrib/ofed/librdmacm/config.h 321936 2017-08-02 16:00:30Z hselasky $ */

#define	min(a, b) ((a) > (b) ? (b) : (a))
#define	VALGRIND_MAKE_MEM_DEFINED(...)	0
#define	s6_addr32 __u6_addr.__u6_addr32
#define	STREAM_CLOEXEC "e"
#define	ENODATA ECONNREFUSED
#define	IBACM_PORT_FILE "/var/run/ibacm.port"

