/*
 * Copyright (c) 2006  Tsuyoshi SAKAMOTO <skmt.japan@gmail.com>,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
*/


/********************************************
 * include file
 ********************************************
*/

/* include */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>		/* FreeBSD */
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <arpa/telnet.h>



/********************************************
 * global type definition
 ********************************************
*/

/*
 * netbuf & termbuf
*/
typedef struct _bufset {
	u_char *buf;
	int bufsz;
	int len;
} bufset;



/*
 * icmpsh data format
 *
 * ICMP
 * +----------+----------+----------+----------+
 * | type(1)  | code(1)  | check sum(2)        |
 * +----------+----------+----------+----------+
 * | packet id(2)        | sequece(2)          |
 * +----------+----------+----------+----------+
 *
 * ICMPSH HEADER
 * +----------+----------+----------+----------+
 * | type(1)  | flag(1)  | tmpflag  | reserve  |
 * +----------+----------+----------+----------+
 * | option(80)                                |
 * +----------+----------+----------+----------+
 * |                                           |
 * +----------+----------+----------+----------+
 * |                     | length(2)           |
 * +----------+----------+----------+----------+
 *
*/

typedef struct _net_termios {	/* struct termios */
	u_long c_iflag;
	u_long c_oflag;
	u_long c_cflag;
	u_long c_lflag;
	u_char c_cc[48]; 	/* reference NCCS in termios.h */
	u_long c_ispeed;
	u_long c_ospeed;
} net_termios;

typedef struct _net_winsz {	/* struct winsize */
	u_short ws_row;
	u_short ws_col;
	u_short ws_xpixel;
	u_short ws_ypixel;
} net_winsz;

typedef struct _icmp_echo {
	u_char type;
	u_char code;
	u_short cksum;
	u_short id;	/* client process id */
	u_short seq;	/* IC_TAG field */
} icmp_echo;

#define IC_IPHLWRS	5	/* number of ip header words (20 bytes) */

#define IC_BUFSIZE	512                               /* ic */
#define IC_REALPAYLOAD	(IC_BUFSIZE - sizeof(ic_header))  /* payload-ich */
#define IC_DATASIZE	(sizeof(icmp_echo) + IC_BUFSIZE)  /* icmp+ic */
#define IC_IPSIZE	(IC_DATASIZE + (IC_IPHLWRS * 4))  /* ip+icmp+ic */

/* icmpsh header */
typedef struct _ic_header_option {
	net_termios ntermios;
	net_winsz nwinsz;
} ic_header_opt;

typedef struct _ic_header {
	u_char type;
	u_char flag;
	u_char tmflag;
	u_char reserve;
	ic_header_opt opt;
	u_short length;
} ic_header;

typedef struct _ic_data {
	struct ip iph;
	icmp_echo icmph;
	union {
		ic_header ich;
		u_char payload[IC_BUFSIZE];
	} data;
} ic_data;


/* tag */
#define IC_TAG		0x1122

/* icmpsh packet type */
#define IC_RESERVE	0x00 /* error handle */
#define IC_START	0x01 /* start session, make co-proc(shell) */
#define IC_START_ACK	0x02 /* ack of IC_START */
#define IC_REQ		0xa1 /* client command request */
#define IC_REPLY	0xb1 /* server command response */
#define IC_QUIT		0xe1 /* end session, kill co-proc(shell) */
#define IC_QUIT_ACK	0xe2 /* ack of IC_QUIT */
#define IC_EOT		0xf1 /* not implement */

/* flag */
#define IC_NORMAL	0x01
#define IC_CONT		0x02 /* not implement */
#define IC_EOD		0x04 /* not implement */

/* termios */
#define IC_TMNOTCH	0x01 /* not changed */
#define IC_TMCHANG	0x02 /* changed */
#define IC_WNNOTCH	0x04 /* not changed */
#define IC_WNCHANG	0x08 /* changed */

/* misc */
#define IC_TIMEOUT	600  /* 600 seconds */



/********************************************
 * constant number and string
 ********************************************
*/
#define ESCAPE	29	/* escape character for icmpsh */



/********************************************
 * misc macro
 ********************************************
*/

/*
 * short cut
*/
#define ICMP_REQ	((opt->echo) ? ICMP_ECHO : ICMP_ECHOREPLY)


/*
 * syslog's level for ic_plog()
*/
#define SEMR	0
#define SALT	1
#define SCRT	2
#define SERR	3
#define SWAR	4
#define SNOT	5
#define SINF	6
#define SDEB	7
#define SNOP	8



/********************************************
 * interface type definition
 ********************************************
*/


/********************************************
* function
********************************************
*/

/*
 * openpty.c
*/
extern int ptym_open(char *);
extern int ptys_open(int, char *);


/*
 * utils.c
*/
extern void ic_plog(int, const char *, ...);
extern void ic_log(const char *, ...);
extern int ic_select(int, long);

#ifdef SOLARIS
extern void cfmakeraw(struct termios *);
#endif

extern void ic_recv_ntohs(ic_data *);
extern void ic_set_termios(net_termios *, struct termios *);
extern void ic_set_winsz(net_winsz *, struct winsize *);
extern void ic_get_termios(struct termios *, net_termios *);
extern void ic_get_winsz(struct winsize *, net_winsz *);
extern void ic_set_data(ic_data *, u_char, u_char, u_short, u_char *, int);
extern void ic_set_header(ic_data *, u_char, u_char, u_short, u_short);

extern int ic_kill(char *, pid_t, int);
extern pid_t ic_waitpid(char *, pid_t, int *, int);

extern ssize_t xread(int, void *, size_t);
extern ssize_t xwrite(int, void *, size_t);

extern void vsys_err(int, const char *, ...);
extern void vsys(int, const char *, ...);

extern unsigned short xchecksum(unsigned short *, int);

extern pid_t xfork(void);

extern void *xmalloc(size_t);
extern void *xrealloc(void *, size_t);
extern char *xstrdup(char *);

/* end of header */
