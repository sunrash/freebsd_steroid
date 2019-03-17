/*-
 * Copyright (c) 2015-2016 Yandex LLC
 * Copyright (c) 2015-2016 Andrey V. Elsukov <ae@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: releng/12.0/sys/netpfil/ipfw/nat64/nat64_translate.h 333403 2018-05-09 11:59:24Z ae $
 */

#ifndef	_IP_FW_NAT64_TRANSLATE_H_
#define	_IP_FW_NAT64_TRANSLATE_H_

struct nat64_stats {
	uint64_t	opcnt64;	/* 6to4 of packets translated */
	uint64_t	opcnt46;	/* 4to6 of packets translated */
	uint64_t	ofrags;		/* number of fragments generated */
	uint64_t	ifrags;		/* number of fragments received */
	uint64_t	oerrors;	/* number of output errors */
	uint64_t	noroute4;
	uint64_t	noroute6;
	uint64_t	nomatch4;	/* No addr/port match */
	uint64_t	noproto;	/* Protocol not supported */
	uint64_t	nomem;		/* mbufs allocation failed */
	uint64_t	dropped;	/* number of packets silently
					 * dropped due to some errors/
					 * unsupported/etc.
					 */

	uint64_t	jrequests;	/* number of jobs requests queued */
	uint64_t	jcalls;		/* number of jobs handler calls */
	uint64_t	jhostsreq;	/* number of hosts requests */
	uint64_t	jportreq;
	uint64_t	jhostfails;
	uint64_t	jportfails;
	uint64_t	jmaxlen;
	uint64_t	jnomem;
	uint64_t	jreinjected;

	uint64_t	screated;
	uint64_t	sdeleted;
	uint64_t	spgcreated;
	uint64_t	spgdeleted;
};

#define	IPFW_NAT64_VERSION	1
#define	NAT64STATS	(sizeof(struct nat64_stats) / sizeof(uint64_t))
struct nat64_counters {
	counter_u64_t		cnt[NAT64STATS];
};
#define	NAT64STAT_ADD(s, f, v)		\
    counter_u64_add((s)->cnt[		\
	offsetof(struct nat64_stats, f) / sizeof(uint64_t)], (v))
#define	NAT64STAT_INC(s, f)	NAT64STAT_ADD(s, f, 1)
#define	NAT64STAT_FETCH(s, f)		\
    counter_u64_fetch((s)->cnt[	\
	offsetof(struct nat64_stats, f) / sizeof(uint64_t)])

#define	L3HDR(_ip, _t)	((_t)((uint32_t *)(_ip) + (_ip)->ip_hl))
#define	TCP(p)		((struct tcphdr *)(p))
#define	UDP(p)		((struct udphdr *)(p))
#define	ICMP(p)		((struct icmphdr *)(p))
#define	ICMP6(p)	((struct icmp6_hdr *)(p))

#define	NAT64SKIP	0
#define	NAT64RETURN	1
#define	NAT64MFREE	-1

struct nat64_config {
	uint32_t		flags;
#define	NAT64_WKPFX		0x00010000	/* prefix6 is WKPFX */
	struct in6_addr		prefix6;
	uint8_t			plen6;

	struct nat64_counters	stats;
};

static inline int
nat64_check_ip6(struct in6_addr *addr)
{

	/* XXX: We should really check /8 */
	if (addr->s6_addr16[0] == 0 || /* 0000::/8 Reserved by IETF */
	    IN6_IS_ADDR_MULTICAST(addr) || IN6_IS_ADDR_LINKLOCAL(addr))
		return (1);
	return (0);
}

static inline int
nat64_check_ip4(in_addr_t ia)
{

	/* IN_LOOPBACK */
	if ((ia & htonl(0xff000000)) == htonl(0x7f000000))
		return (1);
	/* IN_LINKLOCAL */
	if ((ia & htonl(0xffff0000)) == htonl(0xa9fe0000))
		return (1);
	/* IN_MULTICAST & IN_EXPERIMENTAL */
	if ((ia & htonl(0xe0000000)) == htonl(0xe0000000))
		return (1);
	return (0);
}

/* Well-known prefix 64:ff9b::/96 */
#define	IPV6_ADDR_INT32_WKPFX	htonl(0x64ff9b)
#define	IN6_IS_ADDR_WKPFX(a)	\
    ((a)->s6_addr32[0] == IPV6_ADDR_INT32_WKPFX && \
	(a)->s6_addr32[1] == 0 && (a)->s6_addr32[2] == 0)

int nat64_check_private_ip4(const struct nat64_config *cfg, in_addr_t ia);
int nat64_check_prefix6(const struct in6_addr *prefix, int length);
int nat64_getlasthdr(struct mbuf *m, int *offset);
int nat64_do_handle_ip4(struct mbuf *m, struct in6_addr *saddr,
    struct in6_addr *daddr, uint16_t lport, struct nat64_config *cfg,
    void *logdata);
int nat64_do_handle_ip6(struct mbuf *m, uint32_t aaddr, uint16_t aport,
    struct nat64_config *cfg, void *logdata);
int nat64_handle_icmp6(struct mbuf *m, int hlen, uint32_t aaddr,
    uint16_t aport, struct nat64_config *cfg, void *logdata);
void nat64_embed_ip4(const struct nat64_config *cfg, in_addr_t ia,
    struct in6_addr *ip6);
in_addr_t nat64_extract_ip4(const struct nat64_config *cfg,
    const struct in6_addr *ip6);

#endif
