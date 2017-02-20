/*
 * Copyright (c) 1988-2002
 *	The Regents of the University of California.  All rights reserved.
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
 * @(#) $Header: /tcpdump/master/tcpdump/interface.h,v 1.285 2008-08-16 11:36:20 hannes Exp $ (LBL)
 */

#ifndef tcpdump_interface_h
#define tcpdump_interface_h

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

/* snprintf et al */

#include <stdarg.h>

#if HAVE_STDINT_H
#include <stdint.h>
#endif


#ifndef HAVE_STRLCAT
extern size_t strlcat(char *, const char *, size_t);
#endif
#ifndef HAVE_STRLCPY
extern size_t strlcpy(char *, const char *, size_t);
#endif

#ifndef HAVE_STRDUP
extern char *strdup(const char *);
#endif

#ifndef HAVE_STRSEP
extern char *strsep(char **, const char *);
#endif

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

#define ESRC(ep) ((ep)->ether_shost)
#define EDST(ep) ((ep)->ether_dhost)

#ifndef NTOHL
#define NTOHL(x)	(x) = ntohl(x)
#define NTOHS(x)	(x) = ntohs(x)
#define HTONL(x)	(x) = htonl(x)
#define HTONS(x)	(x) = htons(x)
#endif
#endif

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

extern char *program_name;	/* used to generate self-identifying messages */

extern int32_t thiszone;	/* seconds offset from gmt to local time */

/*
 * True if  "l" bytes of "var" were captured.
 *
 * The "snapend - (l) <= snapend" checks to make sure "l" isn't so large
 * that "snapend - (l)" underflows.
 *
 * The check is for <= rather than < because "l" might be 0.
 */
#define TTEST2(var, l) (snapend - (l) <= snapend && \
			(const u_char *)&(var) <= snapend - (l))

/* True if "var" was captured */
#define TTEST(var) TTEST2(var, sizeof(var))

/* Bail if "l" bytes of "var" were not captured */
#define TCHECK2(var, l) if (!TTEST2(var, l)) goto trunc

/* Bail if "var" was not captured */
#define TCHECK(var) TCHECK2(var, sizeof(var))

extern void ts_print(const struct timeval *);
extern void relts_print(int);

extern int fn_print(const u_char *, const u_char *);
extern int fn_printn(const u_char *, u_int, const u_char *);
extern int fn_printzp(const u_char *, u_int, const u_char *);
extern int mask2plen(u_int32_t);
extern const char *tok2strary_internal(const char **, int, const char *, int);
#define	tok2strary(a,f,i) tok2strary_internal(a, sizeof(a)/sizeof(a[0]),f,i)

extern void error(const char *, ...)
     __attribute__((noreturn))
#ifdef __ATTRIBUTE___FORMAT_OK
     __attribute__((format (printf, 1, 2)))
#endif /* __ATTRIBUTE___FORMAT_OK */
     ;
extern void warning(const char *, ...)
#ifdef __ATTRIBUTE___FORMAT_OK
     __attribute__((format (printf, 1, 2)))
#endif /* __ATTRIBUTE___FORMAT_OK */
     ;

extern char *read_infile(char *);
extern char *copy_argv(char **);

extern void safeputchar(int);
extern void safeputs(const char *, int);

extern const char *isonsap_string(const u_char *, register u_int);
extern const char *protoid_string(const u_char *);
extern const char *ipxsap_string(u_short);
extern const char *dnname_string(u_short);
extern const char *dnnum_string(u_short);

/* checksum routines */
extern void init_checksum(void);
extern u_int16_t verify_crc10_cksum(u_int16_t, const u_char *, int);
extern u_int16_t create_osi_cksum(const u_int8_t *, int, int);
extern void ascii_print(const u_char *, u_int);
extern void hex_and_ascii_print_with_offset(const char *, const u_char *, u_int, u_int);
extern void hex_and_ascii_print(const char *, const u_char *, u_int);
extern void hex_print_with_offset(const char *, const u_char *, u_int, u_int);
extern void hex_print(const char *, const u_char *, u_int);

extern int android_printf(const char *format, ...);
extern void android_printf_flush();
extern int android_putchar(int ch);

extern void display_hexdump(const char *title, const u_char *buf, size_t len);

#include <pcap.h>


struct cksum_vec {
	const u_int8_t	*ptr;
	int		len;
};


#include "netdissect.h"

/* forward compatibility */

#ifndef NETDISSECT_REWORKED
extern netdissect_options *gndo;

#define bflag gndo->ndo_bflag 
#define eflag gndo->ndo_eflag 
#define fflag gndo->ndo_fflag 
#define jflag gndo->ndo_jflag
#define Kflag gndo->ndo_Kflag 
#define nflag gndo->ndo_nflag 
#define Nflag gndo->ndo_Nflag 
#define Oflag gndo->ndo_Oflag 
#define pflag gndo->ndo_pflag 
#define qflag gndo->ndo_qflag 
#define Rflag gndo->ndo_Rflag 
#define sflag gndo->ndo_sflag 
#define Sflag gndo->ndo_Sflag 
#define tflag gndo->ndo_tflag 
#define Uflag gndo->ndo_Uflag 
#define uflag gndo->ndo_uflag 
#define vflag gndo->ndo_vflag 
#define xflag gndo->ndo_xflag 
#define Xflag gndo->ndo_Xflag 
#define Cflag gndo->ndo_Cflag 
#define Gflag gndo->ndo_Gflag 
#define Aflag gndo->ndo_Aflag 
#define Bflag gndo->ndo_Bflag 
#define Iflag gndo->ndo_Iflag 
#define packettype gndo->ndo_packettype
#define Hflag gndo->ndo_Hflag
#define snaplen     gndo->ndo_snaplen
#define snapend     gndo->ndo_snapend
#define gENV		gndo->env
#define gPACKET		gndo->packet
#endif
