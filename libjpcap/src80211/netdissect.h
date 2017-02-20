/*
 * Copyright (c) 1988-1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Copyright (c) 1998-2012  Michael Richardson <mcr@tcpdump.org>
 *      The TCPDUMP project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * @(#) $Header: /tcpdump/master/tcpdump/netdissect.h,v 1.27 2008-08-16 11:36:20 hannes Exp $ (LBL)
 */

#ifndef netdissect_h
#define netdissect_h

#include <jni.h>
#include "Jpcap_sub.h"


#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif
#include <sys/types.h>

#ifndef HAVE___ATTRIBUTE__
#define __attribute__(x)
#endif

/* snprintf et al */

#include <stdarg.h>


#ifndef HAVE_STRLCAT
extern size_t strlcat (char *, const char *, size_t);
#endif
#ifndef HAVE_STRLCPY
extern size_t strlcpy (char *, const char *, size_t);
#endif

#ifndef HAVE_STRDUP
extern char *strdup (const char *str);
#endif

#ifndef HAVE_STRSEP
extern char *strsep(char **, const char *);
#endif

struct tok {
	int v;			/* value */
	const char *s;		/* string */
};

#define TOKBUFSIZE 128
extern const char *tok2strbuf(const struct tok *, const char *, int,
			      char *buf, size_t bufsize);

/* tok2str is deprecated */
extern const char *tok2str(const struct tok *, const char *, int);
extern char *bittok2str(const struct tok *, const char *, int);
extern char *bittok2str_nosep(const struct tok *, const char *, int);


typedef struct netdissect_options netdissect_options;

struct netdissect_options {
  int ndo_aflag;		/* translate network and broadcast addresses */
  int ndo_bflag;		/* print 4 byte ASes in ASDOT notation */
  int ndo_eflag;		/* print ethernet header */
  int ndo_fflag;		/* don't translate "foreign" IP address */
  int ndo_Kflag;		/* don't check TCP checksums */
  int ndo_nflag;		/* leave addresses as numbers */
  int ndo_Nflag;		/* remove domains from printed host names */
  int ndo_qflag;		/* quick (shorter) output */
  int ndo_Rflag;		/* print sequence # field in AH/ESP*/
  int ndo_sflag;		/* use the libsmi to translate OIDs */
  int ndo_Sflag;		/* print raw TCP sequence numbers */
  int ndo_tflag;		/* print packet arrival time */
  int ndo_Uflag;		/* "unbuffered" output of dump files */
  int ndo_uflag;		/* Print undecoded NFS handles */
  int ndo_vflag;		/* verbose */
  int ndo_xflag;		/* print packet in hex */
  int ndo_Xflag;		/* print packet in hex/ascii */
  int ndo_Aflag;		/* print packet only in ascii observing TAB,
				 * LF, CR and SPACE as graphical chars
				 */
  int ndo_Bflag;		/* buffer size */
  int ndo_Iflag;		/* rfmon (monitor) mode */
  int ndo_Oflag;                /* run filter code optimizer */
  int ndo_dlt;                  /* if != -1, ask libpcap for the DLT it names*/
  int ndo_jflag;                /* packet time stamp source */
  int ndo_pflag;                /* don't go promiscuous */

  int ndo_Cflag;                /* rotate dump files after this many bytes */
  int ndo_Cflag_count;      /* Keep track of which file number we're writing */
  int ndo_Gflag;            /* rotate dump files after this many seconds */
  int ndo_Gflag_count;      /* number of files created with Gflag rotation */
  int ndo_Hflag;		/* dissect 802.11s draft mesh standard */

  int   ndo_packettype;	/* as specified by -T */
  int   ndo_snaplen;

  /*global pointers to beginning and end of current packet (during printing) */
  const u_char *ndo_snapend;

  JNIEnv *env;
  jobject *packet;	
};

#define PT_VAT		1	/* Visual Audio Tool */
#define PT_WB		2	/* distributed White Board */
#define PT_RPC		3	/* Remote Procedure Call */
#define PT_RTP		4	/* Real-Time Applications protocol */
#define PT_RTCP		5	/* Real-Time Applications control protocol */
#define PT_SNMP		6	/* Simple Network Management Protocol */
#define PT_CNFP		7	/* Cisco NetFlow protocol */
#define PT_TFTP		8	/* trivial file transfer protocol */
#define PT_AODV		9	/* Ad-hoc On-demand Distance Vector Protocol */
#define PT_CARP		10	/* Common Address Redundancy Protocol */
#define PT_RADIUS	11	/* RADIUS authentication Protocol */
#define PT_ZMTP1	12	/* ZeroMQ Message Transport Protocol 1.0 */
#define PT_VXLAN	13	/* Virtual eXtensible Local Area Network */
#define PT_PGM		14	/* [UDP-encapsulated] Pragmatic General Multicast */
#define PT_PGM_ZMTP1	15	/* ZMTP/1.0 inside PGM (native or UDP-encapsulated) */
#define PT_LMP		16	/* Link Management Protocol */

#ifndef min
#define min(a,b) ((a)>(b)?(b):(a))
#endif
#ifndef max
#define max(a,b) ((b)>(a)?(b):(a))
#endif

/*
 * Maximum snapshot length.  This should be enough to capture the full
 * packet on most network interfaces.
 *
 * XXX - could it be larger?  If so, should it?  Some applications might
 * use the snapshot length in a savefile header to control the size of
 * the buffer they allocate, so a size of, say, 2^31-1 might not work
 * well.
 */
#define MAXIMUM_SNAPLEN	65535

/*
 * The default snapshot length is the maximum.
 */
#define DEFAULT_SNAPLEN	MAXIMUM_SNAPLEN

#define ESRC(ep) ((ep)->ether_shost)
#define EDST(ep) ((ep)->ether_dhost)

#ifndef NTOHL
#define NTOHL(x)	(x) = ntohl(x)
#define NTOHS(x)	(x) = ntohs(x)
#define HTONL(x)	(x) = htonl(x)
#define HTONS(x)	(x) = htons(x)
#endif

/*
 * True if "l" bytes of "var" were captured.
 *
 * The "ndo->ndo_snapend - (l) <= ndo->ndo_snapend" checks to make sure
 * "l" isn't so large that "ndo->ndo_snapend - (l)" underflows.
 *
 * The check is for <= rather than < because "l" might be 0.
 */
#define ND_TTEST2(var, l) (ndo->ndo_snapend - (l) <= ndo->ndo_snapend && \
			(const u_char *)&(var) <= ndo->ndo_snapend - (l))

/* True if "var" was captured */
#define ND_TTEST(var) ND_TTEST2(var, sizeof(var))

/* Bail if "l" bytes of "var" were not captured */
#define ND_TCHECK2(var, l) if (!ND_TTEST2(var, l)) goto trunc

extern int fn_print(const u_char *, const u_char *);
extern int fn_printn(const u_char *, u_int, const u_char *);
extern const char *tok2str(const struct tok *, const char *, int);

extern void wrapup(int);


/*
 * Locale-independent macros for testing character properties and
 * stripping the 8th bit from characters.  Assumed to be handed
 * a value between 0 and 255, i.e. don't hand them a char, as
 * those might be in the range -128 to 127.
 */
#define ND_ISASCII(c)	(!((c) & 0x80))	/* value is an ASCII code point */
#define ND_ISPRINT(c)	((c) >= 0x20 && (c) <= 0x7E)
#define ND_ISGRAPH(c)	((c) > 0x20 && (c) <= 0x7E)
#define ND_TOASCII(c)	((c) & 0x7F)

extern void safeputchar(int);
extern void safeputs(const char *, int);

#ifdef LBL_ALIGN
/*
 * The processor doesn't natively handle unaligned loads,
 * and the compiler might "helpfully" optimize memcpy()
 * and memcmp(), when handed pointers that would normally
 * be properly aligned, into sequences that assume proper
 * alignment.
 *
 * Do copies and compares of possibly-unaligned data by
 * calling routines that wrap memcpy() and memcmp(), to
 * prevent that optimization.
 */
extern void unaligned_memcpy(void *, const void *, size_t);
extern int unaligned_memcmp(const void *, const void *, size_t);
#define UNALIGNED_MEMCPY(p, q, l)	unaligned_memcpy((p), (q), (l))
#define UNALIGNED_MEMCMP(p, q, l)	unaligned_memcmp((p), (q), (l))
#else
/*
 * The procesor natively handles unaligned loads, so just use memcpy()
 * and memcmp(), to enable those optimizations.
 */
#define UNALIGNED_MEMCPY(p, q, l)	memcpy((p), (q), (l))
#define UNALIGNED_MEMCMP(p, q, l)	memcmp((p), (q), (l))
#endif


#include <pcap.h>

#endif  /* netdissect_h */
