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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

#include "http_parser.h"

struct options {
  char *ifname;
  char *filter_exp;
  int snaplen;
} options;

static int parse_options(int, char **);
static void show_usage(void);
static pcap_t *pcap_setup(struct options *);

static int
parse_options(int argc, char **argv) {
  /* initialize option parameters */
  options.ifname = NULL;
  options.filter_exp = "tcp and "
    "(dst port 80 or dst port 8000 or dst port 8080)";
  options.snaplen = BUFSIZ;

  int opt;
  while ((opt = getopt(argc, argv, "f:i:s:")) != -1) {
    switch (opt) {
    case 'f':
      options.filter_exp = optarg;
      break;
    case 'i':
      options.ifname = optarg;
      break;
    case 's':
      options.snaplen = atoi(optarg);
      break;
    default:
      return -1;
    }
  }
  if (options.ifname == NULL) {
    return -1;
  }
  return 0;
}

static void
show_usage() {
  printf("urlextractor -i ifname [-f filter_exp] [-s snaplen]\n");
}

static pcap_t *
pcap_setup(struct options *options) {
  pcap_t *handle;
  bpf_u_int32 net, mask;
  struct bpf_program fp;
  char errbuf[PCAP_ERRBUF_SIZE];

  /* open pcap handle */
  if (pcap_lookupnet(options->ifname, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
	    options->ifname, errbuf);
    return NULL;
  }
  handle = pcap_open_live(options->ifname, options->snaplen, 1,
			  1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", options->ifname,
	    errbuf);
    return NULL;
  }

  /* support Ethernet only */
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Device %s doesn't provide Ethernet headers - "
	    "not supported\n", options->ifname);
    return NULL;
  }

  /* setup pcap filter if specified */
  if (options->filter_exp != NULL) {
    if (pcap_compile(handle, &fp, options->filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n",
	      options->filter_exp, pcap_geterr(handle));
      return NULL;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n",
	      options->filter_exp, pcap_geterr(handle));
      return NULL;
    }
  }

  return handle;
}

int
main(int argc, char **argv) {
  pcap_t *pcap_handle;

  if (parse_options(argc, argv) == -1) {
    show_usage();
    exit(EXIT_FAILURE);
  }

  pcap_handle = pcap_setup(&options);
  if (pcap_handle == NULL) {
    exit(EXIT_FAILURE);
  }

  pcap_loop(pcap_handle, 0, http_parser, NULL);

  /* not reached here */
}
