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
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>

#include <errno.h>

#include <syslog.h>
#include <stdarg.h>

#include <string.h>
#include <sys/types.h>
#include <sys/time.h>

#include <termios.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <errno.h>

#include <signal.h>
#include <sys/wait.h>


/********************************************
 * macro
 ********************************************
*/


/********************************************
 * type definition
 ********************************************
*/


/********************************************
 * global variable
 ********************************************
*/
extern int debug;


/* syslog */
const int level[] = {
	LOG_EMERG,
	LOG_ALERT,
	LOG_CRIT,
	LOG_ERR,
	LOG_WARNING,
	LOG_NOTICE,
	LOG_INFO,
	LOG_DEBUG,
	0	/* syslog off */
};


/********************************************
 * proto type
 ********************************************
*/

/* public */

#ifdef SOLARIS
void cfmakeraw(struct termios *);
#endif

int ic_select(int, long);
void ic_plog(int, const char *, ...);
void ic_log(const char *, ...);
void ic_recv_ntohs(ic_data *);
void ic_set_termios(net_termios *, struct termios *);
void ic_set_winsz(net_winsz *, struct winsize *);
void ic_get_termios(struct termios *, net_termios *);
void ic_get_winsz(struct winsize *, net_winsz *);
void ic_set_data(ic_data *, u_char, u_char, u_short, u_char *, int);
void ic_set_header(ic_data *, u_char, u_char, u_short, u_short);
static void ic_convert_data(ic_data *);
static void ic_convert_header(ic_data *);

ssize_t xread(int, void *, size_t);
ssize_t xwrite(int, void *, size_t);

void vsys_err(int, const char *, ...);
void vsys(int, const char *, ...);

u_short xchecksum(u_short *, int);

pid_t xfork(void);

void *xmalloc(size_t);
void *xrealloc(void *, size_t);

char *xstrdup(char *);


/* local */
static int xselect(int, fd_set *, fd_set *, fd_set *, struct timeval *);


/*============================================================================
 * program section
 *============================================================================
*/

#ifdef SOLARIS
/*-------------------------------------------------------------------------
 * cfmakeraw for Solaris
 *
 *-------------------------------------------------------------------------
*/
void
cfmakeraw(struct termios *t)
{
	memset(t, 0, sizeof(struct termios));

	t->c_iflag |= IGNBRK;
	t->c_cflag |= CS8|CREAD;
	t->c_cc[VMIN] = 1;
	t->c_cc[VTIME] = 0;

	return;
}
#endif

/*-------------------------------------------------------------------------
 * termios and window size
 *
 *-------------------------------------------------------------------------
*/
void
ic_set_termios(net_termios *pn, struct termios *pt) {
        int i;
	pn->c_iflag   = htonl(pt->c_iflag);
	pn->c_oflag   = htonl(pt->c_oflag);
	pn->c_cflag   = htonl(pt->c_cflag);
	pn->c_lflag   = htonl(pt->c_lflag);
#ifndef SOLARIS
	pn->c_ispeed  = htonl(pt->c_ispeed);
	pn->c_ospeed  = htonl(pt->c_ospeed);
#endif
	for (i = 0; i < NCCS; ++i) {
		pn->c_cc[i] = pt->c_cc[i];
	}
	return;
}

void
ic_set_winsz(net_winsz *pn, struct winsize *pt) {
	pn->ws_row     = htons(pt->ws_row);
	pn->ws_col     = htons(pt->ws_col);
	pn->ws_xpixel  = htons(pt->ws_xpixel);
	pn->ws_ypixel  = htons(pt->ws_ypixel);
	return;
}

void
ic_get_termios(struct termios *pt, net_termios *pn) {
	int i;
	pt->c_iflag   = ntohl(pn->c_iflag);
	pt->c_oflag   = ntohl(pn->c_oflag);
	pt->c_cflag   = ntohl(pn->c_cflag);
	pt->c_lflag   = ntohl(pn->c_lflag);
#ifndef SOLARIS
	pt->c_ispeed  = ntohl(pn->c_ispeed);
	pt->c_ospeed  = ntohl(pn->c_ospeed);
#endif
	for (i = 0; i < NCCS; ++i) { 
		pt->c_cc[i] = pn->c_cc[i];              
	}       
	return;         
} 

void
ic_get_winsz(struct winsize *pt, net_winsz *pn) {
	pt->ws_row     = ntohs(pn->ws_row);
	pt->ws_col     = ntohs(pn->ws_col);
	pt->ws_xpixel  = ntohs(pn->ws_xpixel);
	pt->ws_ypixel  = ntohs(pn->ws_ypixel);
	return;
}


/*-------------------------------------------------------------------------
 * debug log handler
 *
 *-------------------------------------------------------------------------
*/
void
ic_plog(int lvl, const char *format, ...) {
	va_list ap;
	va_start(ap, format);

	if (debug) {
		vfprintf(stderr, format, ap);
		fprintf(stderr, "\n");
	}
	else {
		if (level[lvl])
			vsyslog(level[lvl], format, ap);
	}

	va_end(ap);

	return;
}

void
ic_log(const char *format, ...) {
	va_list ap;
	va_start(ap, format);

	if (debug) {
		vfprintf(stderr, format, ap);
		fprintf(stderr, "\n");
	}

	va_end(ap);

	return;
}

/*-------------------------------------------------------------------------
 * convert net byte order to host byte order
 *
 *-------------------------------------------------------------------------
*/
void
ic_recv_ntohs(ic_data *pic) {
	char *p;
	struct ip *piph;
	icmp_echo *picmph;
	ic_header *pich;

	p       = (char *)pic;
	piph    = (struct ip *)p;
	picmph  = (icmp_echo *)(p + (IC_IPHLWRS * 4));
	pich    = (ic_header *)(p + (IC_IPHLWRS * 4) + sizeof(icmp_echo));

	ic_convert_header(pic);
	ic_convert_data(pic);

	return;
}


/*-------------------------------------------------------------------------
 * select with error check
 *    arg: the same as select()'s
 *    ret: >=0(success), -1(failure)
 *-------------------------------------------------------------------------
*/
int
xselect(int nfd, fd_set *rfd, fd_set *wfd, fd_set *ofd, struct timeval *pt) {
	int n;

	for (;;) {
		if ((n = select(nfd, rfd, wfd, ofd, pt)) < 0) {
			if (errno == EINTR)
				continue;
		}
		else
			break;
	}

	return (n);
}

/*
 * common select interface for icmsh
*/
int
ic_select(int nfd, long timeout) {
	int n;
	struct timeval tv, *ptv;
	fd_set rfd;

	memset(&rfd, 0, sizeof(rfd));
	tv.tv_sec  = timeout;
	tv.tv_usec = 0;

	ptv = &tv;
	for (;;) {
		FD_ZERO(&rfd);
		FD_SET(nfd, &rfd);
		if ((n = xselect(nfd + 1, &rfd, NULL, NULL, ptv)) < 0) {
			break;
		}
		else if (n == 0) {
			break;
		}
		if (FD_ISSET(nfd, &rfd))
			break;
	}

	return (n);
}


/*-------------------------------------------------------------------------
 * ic_data common interface
 *
 *
 *-------------------------------------------------------------------------
*/
void
ic_set_data(ic_data *p, u_char type, u_char flag, u_short length, u_char *buf, int bufsz) {
	u_char *ppay = (u_char *)&(p->data.payload[0]) + sizeof(ic_header);
	p->data.ich.type    = type;
	p->data.ich.flag    = flag;
	p->data.ich.length  = htons(length);
	if (buf)
		strncpy((char *)ppay, (char *)buf, bufsz);
	return;
}

void
ic_set_header(ic_data *p, u_char type, u_char code, u_short id, u_short seq) {
	p->icmph.type   = type;
	p->icmph.code   = code;
	p->icmph.id     = htons(id);
	p->icmph.seq    = htons(seq);
	p->icmph.cksum  = xchecksum((u_short *)&(p->icmph), IC_DATASIZE);
	return;
}

void
ic_convert_data(ic_data *p) {
	p->data.ich.length  = ntohs(p->data.ich.length);
	return;
}

void
ic_convert_header(ic_data *p) {
	p->icmph.id     = ntohs(p->icmph.id);
	p->icmph.seq    = ntohs(p->icmph.seq);
	return;
}


/*-------------------------------------------------------------------------
 * send / wait signal
 *
 *-------------------------------------------------------------------------
*/
int
ic_kill(char *proc, pid_t p, int sig) {
	int rc;
	if ((rc = kill(p, sig)) != 0)
		ic_plog(SINF, "(%s) kill failure (%s)", proc, strerror(errno));

	return (rc);
}

pid_t
ic_waitpid(char *proc, pid_t p, int *status, int options) {
	pid_t wpid;
	if ((wpid = waitpid(p, status, options)) < 0)
		ic_plog(SINF, "(%s) waitpid failure (%s)", proc, strerror(errno));

	return (wpid);
}


/*-------------------------------------------------------------------------
 * read with error check
 *
 *-------------------------------------------------------------------------
*/
ssize_t
xread(int fd, void *buff, size_t size)
{
	size_t left;
	ssize_t nread;

	void *p;

	p = buff;
	left = size;

	while (left > 0) {
		if ((nread = read(fd, p, left)) < 0) {
			if (errno == EINTR)
				nread = 0;
			else
				return (-1);
		}
		else if (nread == 0) {
			break;
		}
		left -= nread;
		p = (char *)p + nread;
	}

	return (size - left);
}


/*-------------------------------------------------------------------------
 * write with error check
 *
 *-------------------------------------------------------------------------
*/
ssize_t
xwrite(int fd, void *buff, size_t size)
{
	size_t left;
	ssize_t nwrite;

	void *p;

	p = buff;
	left = size;

	while (left > 0) {
		if ((nwrite = write(fd, p, left)) < 0) {
			if (errno == EINTR)
				nwrite = 0;
			else
				return (-1);
		}
		left -= nwrite;
		p = (char *)p + nwrite;
	}

	return size;
}


/*-------------------------------------------------------------------------
 * syslog interface
 *
 *-------------------------------------------------------------------------
*/
void
vsys_err(int priority, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vsyslog(priority, format, ap);

	va_end(ap);

	exit(1);
}

void
vsys(int priority, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vsyslog(priority, format, ap);

	va_end(ap);

	return;
}


/*-------------------------------------------------------------------------
 * internet checksum
 *
 *-------------------------------------------------------------------------
*/
u_short
xchecksum(u_short *addr, int len) {
	u_short answer;
	u_short *w;
	int nleft, sum;

	nleft = len;
	sum = 0;
	w = addr;
	while (nleft > 1) {
		sum += *(w++);
		nleft -= 2;
	}
	if (nleft == 1)
		sum += *(u_char *) w;

	sum = (sum & 0xffff) + (sum >> 16);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}


/*-------------------------------------------------------------------------
 * fork with error check
 *
 *-------------------------------------------------------------------------
*/
pid_t
xfork(void)
{
	pid_t pid;

	if ((pid = fork()) < 0) {
		ic_plog(SERR, "xfork failure due to fork error");
		exit(1);
	}

	return (pid);
}


/*-------------------------------------------------------------------------
 * malloc family with error check
 *
 *-------------------------------------------------------------------------
*/
void *
xmalloc(size_t size)
{
	void *tmp;

	if (!size) {
		ic_plog(SERR, "xmalloc failure due to invalid size");
		exit (1);
	}

	if ((tmp = malloc(size)) == NULL) {
		ic_plog(SERR, "xmalloc failure due to malloc error");
		exit (1);
	}
	else {
		memset(tmp, 0, size);
	}

	return (tmp);
}

void *
xrealloc(void *src, size_t size)
{
	void *dst;

	if (!size) {
		ic_plog(SERR, "xrealloc failure due to invalid size");
		exit (1);
	}

	if ((dst = realloc(src, size)) == NULL) {
		ic_plog(SERR, "xrealloc failure due to realloc error");
		exit (1);
	}

	return (dst);
}


/*-------------------------------------------------------------------------
 * strdup with error check
 *
 *-------------------------------------------------------------------------
*/
char *
xstrdup(char *ptr)
{
	char *tmp;

	if (!ptr) {
		ic_plog(SERR, "xstrdup failure due to invalid pointer");
		exit (1);
	}

	if ((tmp = strdup(ptr)) == NULL) {
		ic_plog(SERR, "xstrdup failure due to strdup error");
		exit (1);
	}

	return (tmp);
}


/* end of source */
