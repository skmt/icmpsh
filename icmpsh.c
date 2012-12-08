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
#include "icmpsh.h"

#include <stdio.h>
#include <libgen.h>
#include <string.h>
#include <strings.h>

#include <errno.h>

#include <sys/types.h>
#include <unistd.h>

#include <ctype.h>
#include <signal.h>
#include <sys/wait.h>

#include <stdlib.h>

#include <syslog.h>

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h>

#include <stdarg.h>

#include <sys/ioctl.h>
#ifdef SOLARIS
 #include <stropts.h>
 #include <sys/filio.h>
#endif


/********************************************
 * macro
 ********************************************
*/
#define DEFAULT_IP		"127.0.0.1"



/********************************************
 * type definition
 ********************************************
*/

/*
 * for short-cut
*/
typedef struct sockaddr SA;
typedef struct sockaddr_in SA_IN;
typedef struct in_addr ADDR;


/*
 * options
*/
typedef struct _opt {
	int echo;
	char *psrc;
	char *pdst;
	SA *src;
	socklen_t srclen;
	SA *dst;
	socklen_t dstlen;
	pid_t pid;
	int timeout;
} OPT;



/********************************************
 * global variable
 ********************************************
*/
int debug = 0;

static char *program   = NULL;

/* options */
static OPT *opt;

/* raw socket */
static int sockin  = -1;
static int sockout = -1;

/* network and tty buffer */
static bufset netbuf;
static bufset termbuf;



/********************************************
 * proto type
 ********************************************
*/


/*============================================================================
 * program section
 *============================================================================
*/
/*-------------------------------------------------------------------------
 * print usage and die
 *-------------------------------------------------------------------------
*/
void
ic_print_usage(void) {
	fprintf(stdout, "usage: %s [option(s)] target\n"
	"\t[-d]         print debug information \n"
	"\t[-i host]    binding interface [not implemented] \n"
	"\t[-q]         use icmp-echo and reply (reply only by default) \n"
	"\t[-t sec]     session timeout \n",
	program);

	exit(1);
}


/*-------------------------------------------------------------------------
 * set option
 *-------------------------------------------------------------------------
*/
void
ic_option(int argc, char **argv) {
	int ch;
	struct addrinfo dst_hints, src_hints;
	struct addrinfo *dst, *src;
	int out;

	opt = xmalloc(sizeof(OPT));

	program       = xstrdup(basename(argv[0]));
	opt->psrc     = DEFAULT_IP;
	opt->pdst     = DEFAULT_IP;
	opt->pid      = getpid();
	opt->timeout  = IC_TIMEOUT;

	while ((ch = getopt(argc, argv, "dhiqt:")) != -1) {
		switch(ch) {
		case 'd':
			debug = 1;
			break;
		case 'h':
			ic_print_usage();
			break;
		case 'i':
			opt->psrc = xstrdup(optarg);
			break;
		case 'q':
			opt->echo = 1;
			break;
		case 't':
			if ((out = atoi(optarg)) > 0 && out < IC_TIMEOUT)
				opt->timeout = out;
			break;
		default:
			ic_print_usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc)
		opt->pdst = xstrdup(*argv);

	/*
	 * get host info
	*/
	memset(&dst_hints, 0, sizeof(dst_hints));
	dst_hints.ai_flags    = AI_CANONNAME;
	dst_hints.ai_family   = AF_INET;
	dst_hints.ai_socktype = SOCK_RAW;
	if (getaddrinfo(opt->pdst, (char *)NULL, &dst_hints, &dst) != 0) {
		ic_log("getaddrinfo() failure, destination");
		exit (1);
	}
	opt->dst = dst->ai_addr;
	opt->dstlen = dst->ai_addrlen;

	memset(&src_hints, 0, sizeof(src_hints));
	src_hints.ai_flags    = AI_CANONNAME;
	src_hints.ai_family   = AF_INET;
	src_hints.ai_socktype = SOCK_RAW;
	if (getaddrinfo(opt->psrc, (char *)NULL, &src_hints, &src) != 0) {
		ic_log("getaddrinfo() failure, source");
		exit (1);
	}
	opt->src = src->ai_addr;
	opt->srclen = src->ai_addrlen;

	return;
}


/*-------------------------------------------------------------------------
 * write to network
 *
 *-------------------------------------------------------------------------
*/
int
ic_write_network(bufset *nbuf) {
	int iclen;
	ic_data dg;
	icmp_echo *picmph = &(dg.icmph);
	int send;
	u_short pid = opt->pid;

	/*
	 * if size of netbuf is bigger than IC_REALPAYLOAD(ic_data's
	 * payload), it has to split a netbuf in two (or more).
	*/
	while (nbuf->len > 0) {
		if (nbuf->len > IC_REALPAYLOAD) {
			iclen = IC_REALPAYLOAD;
			nbuf->len -= IC_REALPAYLOAD;
		}
		else {
			iclen = nbuf->len;
			nbuf->len = 0;
		}
		memset(&dg, 0, sizeof(dg));
		ic_set_data(&dg, IC_REQ, IC_NORMAL, iclen, nbuf->buf, iclen);
		ic_set_header(&dg, ICMP_REQ, 0, pid, IC_TAG);
		for (;;) {
			send = sendto(sockout, (icmp_echo *)picmph, IC_DATASIZE, 0, opt->dst, opt->dstlen);
			if (send < 0) {
				if (errno == ENOBUFS)
					continue;
				ic_log("-> can not send packet (%s)", strerror(errno));
				return (-1);
			}
			else if (send == IC_DATASIZE) {
				break;
			}
			ic_log("-> invalid data size sent, retry to send");
		}
	}

	return (0);
}


/*-------------------------------------------------------------------------
 * write to tty
 *
 *-------------------------------------------------------------------------
*/
int
ic_write_tty(bufset *tbuf) {
	(void) xwrite(STDOUT_FILENO, tbuf->buf, tbuf->len);
	tbuf->len = 0;
	return (0);
}

/*-------------------------------------------------------------------------
 * read from tty
 *
 *-------------------------------------------------------------------------
*/
int
ic_read_tty(bufset *nbuf) {
	int cc;
	u_char tempbuff[BUFSIZ];

	for (;;) {
		cc = read(STDIN_FILENO, tempbuff, nbuf->bufsz);
		if (cc < 0) {
			if (errno == EINTR)
				continue;
			else
				return (0);
		}
		else
			break;
	}

	if (cc > 0 && tempbuff[0] == ESCAPE)
		return (-1); /* quit immediately */
	else {
		if ((nbuf->len + cc) > nbuf->bufsz) {
			nbuf->bufsz *= 2;
			nbuf->buf = xrealloc(nbuf->buf, nbuf->bufsz);
			ic_log("-> expand netbuf (%d)", nbuf->bufsz);
		}
		memcpy(nbuf->buf + nbuf->len, tempbuff, cc);
		nbuf->len += cc;
	}
		
	return (cc);
}

/*-------------------------------------------------------------------------
 # read from network
 *
 *-------------------------------------------------------------------------
*/
u_char
ic_is_icmpsh_client(ic_data *p, u_short pid) {
	u_char type;

	if (p->iph.ip_hl != IC_IPHLWRS)
		return (IC_RESERVE);

	if (p->icmph.type  == ICMP_ECHOREPLY &&
	    p->icmph.id    == pid            &&
	    p->icmph.seq   == IC_TAG)
		type = p->data.ich.type;
	else
		return (IC_RESERVE);

	ic_log("dg.iph.ip_src    (%s)", inet_ntoa(p->iph.ip_src));
	ic_log("dg.iph.ip_dst    (%s)", inet_ntoa(p->iph.ip_dst));
	ic_log("dg.icmph.type    (%d)", p->icmph.type);
	ic_log("dg.icmph.code    (%d)", p->icmph.code);
	ic_log("dg.icmph.id      (%d)", p->icmph.id);
	ic_log("dg.icmph.seq     (%d)", p->icmph.seq);
	ic_log("dg.data.ich.type (%d)", p->data.ich.type);

	if (type == IC_REPLY || type == IC_EOT)
		return (type);

	return (IC_RESERVE);
}

int
ic_read_network(bufset *tbuf) {
	ic_data dg;
	ic_header *pich   = &(dg.data.ich);
	u_char *ppayload  = (u_char *)&(dg.data.payload[0]) + sizeof(ic_header);
	int recv;   /* length of ip datagram */
	u_short pid = opt->pid;
	u_char type;
	SA_IN src;
	socklen_t srclen;

	for (;;) {
		memset(&dg, 0, sizeof(dg));
		recv = recvfrom(sockin, (ic_data *)&dg, sizeof(dg), 0, (SA *)&src, &srclen);
		if (recv == IC_IPSIZE) {
			ic_recv_ntohs(&dg);
			if ((type = ic_is_icmpsh_client(&dg, pid)) == IC_REPLY) {
				if ((tbuf->len + pich->length) > tbuf->bufsz) {
					tbuf->bufsz *= 2;
					tbuf->buf = xrealloc(tbuf->buf, tbuf->bufsz);
					ic_log("-> expand termbuf (%d)", tbuf->bufsz);
				}
				ic_log("-> accepted data (%d)", pich->length);
				strncpy((char *)(tbuf->buf + tbuf->len), (char *)ppayload, pich->length);
				tbuf->len += pich->length;
				return (0);
			}
			else if (type == IC_EOT) {
				ic_log("quit, due to receiving IC_EOT");
				return (-1);
			}
			ic_log("mismatch icmpsh packet, ignored");
			continue;
		}
		else if (recv < 0) {
			if (errno == EINTR)
				continue;
			ic_log("-> error occurd, ignore incoming packet");
			break;
		}
		ic_log("-> non-icmpsh data received, ignored");
		break;
	}

	return (0);
}


/*-------------------------------------------------------------------------
 * icmpsh start and finish handshake
 *
 *-------------------------------------------------------------------------
*/

/*
 * interface of sending, receiving handshake packet
 *    success, return value 0
 *    fail, return value -1
 *    recoverable fail, return value 1
*/
int
ic_handshake_sendto(icmp_echo *p) {
	int cc;
	int retry;

	for (retry = 0; retry < 5; ++retry) {
		cc = sendto(sockout, p, IC_DATASIZE, 0, opt->dst, opt->dstlen);
		if (cc < 0) {
			ic_log("-> handshake_1 failure (%s)", strerror(errno));
			if (errno == ENOBUFS)
				sleep (3);
			else
				return (-1);
		}
		else if (cc == IC_DATASIZE) {
			return (0); /* success */
		}
		ic_log("-> invalid data sent, retry to send");
	}

	/* fail */
	return (1);
}

int
ic_handshake_recvfrom(ic_data *p, u_char type) {
	int recv;
	int retry;
	u_short pid = opt->pid;
	SA_IN src;
	socklen_t srclen;
	ic_data dg;

	for (retry = 0; retry < 5; ++retry) {
		if (ic_select(sockin, IC_TIMEOUT) <= 0)
			break;
		memset(&dg, 0, sizeof(dg));
		recv = recvfrom(sockin, (ic_data *)&dg, sizeof(dg), 0, (SA *)&src, &srclen);
		if (recv < 0) {
			ic_log("-> handshake_2 failure(%s)", strerror(errno));
			if (errno == EINTR)
				sleep (3);
			else
				return (-1);
		}
		else if (recv == IC_IPSIZE) {
			ic_recv_ntohs(&dg);
			if (dg.icmph.type     == ICMP_ECHOREPLY &&
			    dg.icmph.id       == pid &&
			    dg.icmph.seq      == IC_TAG &&
			    dg.data.ich.type  == type) {
				ic_log("-> received ack from (%s)", inet_ntoa(dg.iph.ip_src));
				*p = dg;
				return (0);
			}
		}
		ic_log("-> invalid data received, retry to receive");
	}

	/* fail */
	return (1);
}

int
ic_start(struct winsize *pw) {
	ic_data sdg, rdg;
	icmp_echo *psdg = (icmp_echo *)&(sdg.icmph);
	u_short pid = opt->pid;
	int retry;

	ic_log("-> starting icmsh, opened socket (in:%d, out:%d)", sockin, sockout);

	memset(&sdg, 0, sizeof(sdg));
	ic_set_data(&sdg, IC_START, IC_NORMAL, 0, NULL, 0);
	if (pw) {
		sdg.data.ich.tmflag |= IC_WNCHANG;
		ic_set_winsz(&(sdg.data.ich.opt.nwinsz), pw);
	}
	ic_set_header(&sdg, ICMP_REQ, 0, pid, IC_TAG);

	for (retry = 0; retry < 5; ++retry) {
		int sc, rc;
		if ((sc = ic_handshake_sendto(psdg)) == -1)
			break;
		else if (sc == 1)
			continue;

		memset(&rdg, 0, sizeof(rdg));
		if ((rc = ic_handshake_recvfrom(&rdg, IC_START_ACK)) == -1)
			break;
		else if (rc == 0)
			return (0);
		ic_log("-> retry to send starting packet [%d]", retry);
	}

	return (-1);
}

int
ic_finish(void) {
	ic_data sdg, rdg;
	icmp_echo *psdg = (icmp_echo *)&(sdg.icmph);
	u_short pid = opt->pid;
	int retry;

	ic_log("-> finishing icmsh");

	memset(&sdg, 0, sizeof(sdg));
	ic_set_data(&sdg, IC_QUIT, IC_NORMAL, 0, NULL, 0);
	ic_set_header(&sdg, ICMP_REQ, 0, pid, IC_TAG);

	for (retry = 0; retry < 5; ++retry) {
		int sc, rc;
		if ((sc = ic_handshake_sendto(psdg)) == -1)
			break;
		else if (sc == 1)
			continue;

		memset(&rdg, 0, sizeof(rdg));
		if ((rc = ic_handshake_recvfrom(&rdg, IC_QUIT_ACK)) == -1 )
			break;
		else if (rc == 0)
			return (0);
		ic_log("-> retry to send finishing packet [%d]", retry);
	}

	return (-1);
}


/*-------------------------------------------------------------------------
 * signal hander
 *-------------------------------------------------------------------------
*/

/*
 * send sigquit, CTRL-\
*/
void
ic_sendquit(int signo) {
	static u_char payload[BUFSIZ] = { IAC, ABORT, 0 };
	bufset urgebuf = { payload, sizeof(payload), 2 };
	(void) ic_write_network(&urgebuf);
	return;
}

void
ic_catch_sigquit(void) {
	struct sigaction act, oact;

	act.sa_handler = ic_sendquit;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	if (sigaction(SIGQUIT, &act, &oact) < 0)
		ic_log("can not set signal hander SIGQUIT");

	return;
}

/*
 * send sigint, CTRL-C
*/
void
ic_sendint(int signo) {
	static u_char payload[BUFSIZ] = { IAC, IP, 0 };
	bufset urgebuf = { payload, sizeof(payload), 2 };
	(void) ic_write_network(&urgebuf);
	return;
}

void
ic_catch_sigint(void) {
	struct sigaction act, oact;

	act.sa_handler = ic_sendint;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	if (sigaction(SIGINT, &act, &oact) < 0)
		ic_log("can not set signal hander SIGINT");

	return;
}

/*
 * send sigtstp, CTRL-Z
*/
void
ic_sendtstp(int signo) {
	static u_char payload[BUFSIZ] = { IAC, SUSP, 0 };
	bufset urgebuf = { payload, sizeof(payload), 2 };
	(void) ic_write_network(&urgebuf);
	return;
}

void
ic_catch_sigtstp(void) {
	struct sigaction act, oact;

	act.sa_handler = ic_sendtstp;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	if (sigaction(SIGTSTP, &act, &oact) < 0)
		ic_log("can not set signal hander SIGTSTP");

	return;
}


void
ic_signal() {
	ic_catch_sigquit();
	ic_catch_sigint();
	ic_catch_sigtstp();

	return;
}


/*-------------------------------------------------------------------------
 * main
 *-------------------------------------------------------------------------
*/
void
ic_original_termios(struct termios *p) {
	(void) tcsetattr(STDIN_FILENO, TCSAFLUSH, p);
	return;
}

int
ic_init_terminal(struct termios tt) {
	struct termios rtt = tt;
	int on = 1;

	rtt.c_lflag &= ~(ECHO|ICANON);
	rtt.c_cc[VMIN] = 1;
	rtt.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &rtt) == -1)
		ic_log("tcsetattr error (%s)", strerror(errno));

	if (ioctl(STDIN_FILENO, FIONBIO, (char *)&on) == -1) {
		ic_log("ioctl error stdin (%s)", strerror(errno));
		return (-1);
	}
	if (ioctl(STDOUT_FILENO, FIONBIO, (char *)&on) == -1) {
		ic_log("ioctl error stdout (%s)", strerror(errno));
		return (-1);
	}
	if (ioctl(sockin, FIONBIO, (char *)&on) == -1) {
		ic_log("ioctl error sockin (%s)", strerror(errno));
		return (-1);
	}
	if (ioctl(sockout, FIONBIO, (char *)&on) == -1) {
		ic_log("ioctl error sockout (%s)", strerror(errno));
		return (-1);
	}

	return (0);
}

void
ic_make_buf() {
	netbuf.buf = xmalloc(IC_REALPAYLOAD);
	netbuf.bufsz = IC_REALPAYLOAD;
	netbuf.len = 0;
	termbuf.buf = xmalloc(IC_REALPAYLOAD);
	termbuf.bufsz = IC_REALPAYLOAD;
	termbuf.len = 0;
	ic_log("-> made buffer (netbuf: %d bytes)", netbuf.bufsz);
	ic_log("-> made buffer (termbuf: %d bytes)", termbuf.bufsz);

	return;
}

int
main(int argc, char **argv) {
	int uid;
	int maxfd;
	fd_set rfd, wfd;
	struct termios tt;	/* original termios */
	struct winsize win;

	ic_option(argc, argv);

	if ((sockin  = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
		ic_log("socket failure in(%d)", sockin);
	if ((sockout = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
		ic_log("socket failure out(%d)", sockout);

	/* renounce privilege */
	if ((uid = getuid()) > 0)
		setuid(uid);

	if (isatty(STDIN_FILENO)) {
		if (tcgetattr(STDIN_FILENO, &tt) == -1)
			return (1);
		if (ioctl(STDIN_FILENO, TIOCGWINSZ, &win) == -1)
			return (1);
		if (ic_init_terminal(tt) == -1)
			return (1);
	}
	else
		return (1);

	/*
	 * main loop
	*/
	if (ic_start(&win) < 0) {
		ic_original_termios(&tt);
		return (1);
	}

	fprintf(stderr, "Start icmpsh, escape sequence is ^]\n");
	ic_signal();
	ic_make_buf();

	maxfd = (sockin > sockout) ? sockin : sockout;
	FD_ZERO(&rfd);
	FD_ZERO(&wfd);
	for (;;) {
		int nfd;
		FD_ZERO(&wfd);
		if (netbuf.len > 0)
			FD_SET(sockout, &wfd);
		if (termbuf.len > 0)
			FD_SET(STDOUT_FILENO, &wfd);
		FD_SET(STDIN_FILENO, &rfd);
		FD_SET(sockin, &rfd);
		ic_log("-> waiting (in:%d, out:%d)", sockin, sockout);
		nfd = select(maxfd + 1, &rfd, &wfd, 0, 0);
		ic_log("-> return select() -> %d", nfd);
		if (nfd < 0 && errno != EINTR)
			break;
		if (nfd > 0 && netbuf.len > 0 && FD_ISSET(sockout, &wfd))
			(void) ic_write_network(&netbuf);
		if (nfd > 0 && termbuf.len > 0 && FD_ISSET(STDOUT_FILENO, &wfd))
			(void) ic_write_tty(&termbuf);
		if (nfd > 0 && FD_ISSET(STDIN_FILENO, &rfd)) {
			if (ic_read_tty(&netbuf) < 0)
				break;
		}
		if (nfd > 0 && FD_ISSET(sockin, &rfd)) {
			if (ic_read_network(&termbuf) < 0)
				break;
		}
	}

	if (ic_finish() < 0) {
		fprintf(stderr, "\nAbnormal finish icmpsh\n");
		return (1);
	}

	ic_original_termios(&tt);

	fprintf(stderr, "\nFinish icmpsh, bye ;-)\n");
	return (0);
}

/* end of source */
