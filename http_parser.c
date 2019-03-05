/*
 * Copyright 2018 IIJ Innovation Institute Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <arpa/inet.h>
#include <string.h>

#include <pcap.h>

#include "picohttpparser.h"
#include "http_parser.h"

/* Ethernet header */
struct sniff_ethernet {
  u_int8_t dst[6];
  u_int8_t src[6];
  /* type follows */
};

struct sniff_ethernet_q {
  u_int8_t dst[6];
  u_int8_t src[6];
  u_int16_t tpid;
  u_int16_t tci;
  /* type follows */
};

struct sniff_ethernet_qinq {
  u_int8_t dst[6];
  u_int8_t src[6];
  u_int16_t tpid1;
  u_int16_t tci1;
  u_int16_t tpid2;
  u_int16_t tci2;
  /* type follows */
};

struct sniff_ethernet_type {
  /* ethernet header */
  u_int16_t type;
};

/* IPv4 header */
struct sniff_ip4 {
  u_int8_t vhl;
  u_int8_t tos;
  u_int16_t len;
  u_int16_t id;
  u_int16_t off;
  u_int8_t ttl;
  u_int8_t proto;
  u_int16_t sum;
  struct in_addr src;
  struct in_addr dst;
};

/* IPv6 header */
struct sniff_ip6 {
  u_int32_t vtf;
  u_int16_t plen;
  u_int8_t nh;
  u_int8_t hlim;
  u_int8_t src[16];
  u_int8_t dst[16];
};

/* TCP header */
struct sniff_tcp {
  u_int16_t sport;
  u_int16_t dport;
  u_int32_t seq;
  u_int32_t ack;
  u_int8_t offx2;
  u_int8_t flags;
  u_int16_t win;
  u_int16_t sum;
  u_int16_t urp;
};

void
http_parser(u_char *user, const struct pcap_pkthdr *pkthdr,
	    const u_char *pkt) {
  struct sniff_ethernet_type *et = (struct sniff_ethernet_type *)(pkt + 12);
  struct sniff_tcp *tcp;
  char ip_src[40], ip_dst[40];

  /* skip VLAN tags */
  if (ntohs(et->type) == 0x8100) {
    et = (struct sniff_ethernet_type *)(pkt
					+ sizeof(struct sniff_ethernet_q));
  } else if (ntohs(et->type) == 0x88a8) {
    et = (struct sniff_ethernet_type *)(pkt
					+ sizeof(struct sniff_ethernet_qinq));
  } else {
    et = (struct sniff_ethernet_type *)(pkt
					+ sizeof(struct sniff_ethernet));
  }

  /* parse network protocol headers and get a pointer to TCP header */
  if (ntohs(et->type) == 0x0800) {
    /* IPv4 */
    struct sniff_ip4 *ip4 = (struct sniff_ip4 *)(et + 1);
    u_int ip4_hlen = (ip4->vhl & 0x0f) << 2;
    /* get src and dst addresses in strings */
    inet_ntop(AF_INET, (const void *)&ip4->src, ip_src, sizeof(ip_src));
    inet_ntop(AF_INET, (const void *)&ip4->dst, ip_dst, sizeof(ip_dst));
    tcp = (struct sniff_tcp *)((u_char *)ip4 + ip4_hlen);
  } else if (ntohs(et->type) == 0x86dd) {
    /* IPv6 */
    struct sniff_ip6 *ip6 = (struct sniff_ip6 *)(et + 1);
    u_int ip6_hlen = sizeof(struct sniff_ip6);
    /* get src and dst addresses in strings */
    inet_ntop(AF_INET6, (const void *)&ip6->src, ip_src, sizeof(ip_src));
    inet_ntop(AF_INET6, (const void *)&ip6->dst, ip_dst, sizeof(ip_dst));
    if (ip6->nh != 6) {
      /* XXX should follow a header chain and update ip6_hlen */
      return;
    }
    tcp = (struct sniff_tcp *)((u_char *)ip6 + ip6_hlen);
  } else {
    /* ignore non IP packets */
    return;
  }

  /* parse http */
  /* assuming that non http packets are filtered in pcap_loop() */
  u_int tcp_hlen = (tcp->offx2 & 0xf0) >> 2;
  u_char *http = (u_char *)tcp + tcp_hlen;
  u_int http_len = pkthdr->caplen - (http - pkt);
  const char *method;
  size_t method_len;
  const char *path;
  size_t path_len;
  int minor_version;
  struct phr_header headers[128];
  size_t num_headers = sizeof(headers) / sizeof(headers[0]);

  if (http_len <= 0) {
    return;
  }
  if (phr_parse_request((char *)http, http_len, &method, &method_len,
			&path, &path_len, &minor_version,
			headers, &num_headers,
			http_len) < 0) {
    return;
  }

  const char *host = NULL;
  int host_len = 0;
  int i;
  for (i = 0; i != num_headers; ++i) {
    if (memcmp("Host", headers[i].name, strlen("Host")) == 0
	&& strlen("Host") == headers[i].name_len) {
      host = headers[i].value;
      host_len = headers[i].value_len;
    }
  }

  if (host == NULL) {
    printf("%s %s %s%.*s\n", ip_src, ip_dst,
	   ip_dst, (int)path_len, path);
  } else {
    printf("%s %s %.*s%.*s\n", ip_src, ip_dst,
	   host_len, host, (int)path_len, path);
  }
  fflush(stdout);
}
