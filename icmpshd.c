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
 #include <sac.h>
 #include <utmpx.h>
#endif



/********************************************
 * macro
 ********************************************
*/
#define MAXHOSTLEN		256
#define MAXFD			256
#define DEFAULT_DIR		"/var/tmp"
#define DEFAULT_PIDFILE		"icmpshd.pid"
#define DEFAULT_IP		"127.0.0.1"
#define DEFAULT_INTERVAL	1800

#define MAXFD3(max, a, b, c)	\
{ \
	max = (a > b) ? a : b; \
	max = (max > c) ? max : c; \
}


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
	char *dir;
	char *ip;
	SA *src;
	socklen_t srclen;
	char *user;
	int fac;
	time_t timeout;
	struct termios origtt;
	char *pidfile;
} OPT;


/*
 * process database
 *
 * Process database stores informations, including remote host name, ip address,
 * and process id of icmpsh(NOT icmpshd), and keep it inside icmpshd to determine
 * which co-process icmpshd will transfer a datagram to.
 *
*/
typedef struct _proc_db {
	struct _proc_db *next;
	ADDR client;	/* key(1): client ip address */
	u_short id;	/* key(2): process id of remote host */
	pid_t shelldrv;	/* key(3): child's pid (ic_shell_driver) */
	char clientname[MAXHOSTLEN];
	ADDR local;
	int fd;
	time_t create; 	/* create time */
	time_t last;	/* last access time */
} proc_db;



/********************************************
 * global variable
 ********************************************
*/
int debug = 0;

static char *program   = NULL;

static int sockin  = -1;
static int sockout = -1;


/*
 * syslog facility and level
*/
const int facility[] = {
	LOG_LOCAL0,
	LOG_LOCAL1,
	LOG_LOCAL2,
	LOG_LOCAL3,
	LOG_LOCAL4,
	LOG_LOCAL5,
	LOG_LOCAL6,
	LOG_LOCAL7
};



/********************************************
 * proto type
 ********************************************
*/
/* misc */
static void ic_print_usage(void);
static OPT *ic_option(int, char **);
static void ic_go_daemon(OPT *);

/* signal handler for listener process */
static void ic_ignore_sighup(void);
static void ic_sig_chld(int);
static void ic_catch_status(void);

/* process database utils */
static proc_db * ic_db_make_list(void);
static void ic_db_lock(void);
static void ic_db_unlock(void);
static void ic_db_cleanup(void);
static int ic_db_cleanup_old(time_t, time_t);
static void ic_db_make(int);
static int ic_db_nrecord(void);
static proc_db * ic_db_insert(ic_data *, int);
static proc_db * ic_db_remove(ic_data *);
static proc_db * ic_db_find(ic_data *, int);
static proc_db * ic_db_find_pid(pid_t);

/* request handler */
static int ic_reply(u_char, proc_db *);
static int ic_req_start(ic_data *, char **, OPT *);
static int ic_req_req(ic_data *);
static int ic_req_quit(ic_data *);


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
	"\t[-d]        print debug information, not daemon mode \n"
	"\t[-f fac]    syslog facility \n"
	"\t[-i ip]     bind ip address \n"
	"\t[-p pid]    change pid file \n"
	"\t[-r dir]    change root directory \n"
	"\t[-t sec]    internal database clean-up interval (for debug) \n",
	program);

	exit(1);
}


/*-------------------------------------------------------------------------
 * set option
 *-------------------------------------------------------------------------
*/
OPT *
ic_option(int argc, char **argv) {
	OPT *opt;
	int ch;
	int i;
	struct addrinfo hints;
	struct addrinfo *src;

	opt = xmalloc(sizeof(OPT));

	program       = xstrdup(basename(argv[0]));
	opt->dir      = DEFAULT_DIR;
	opt->ip       = DEFAULT_IP;
	opt->fac      = facility[0];
	opt->timeout  = DEFAULT_INTERVAL;
	opt->pidfile  = DEFAULT_PIDFILE;

	if (tcgetattr(STDIN_FILENO, &(opt->origtt)) == -1)
		ic_plog(SDEB, "(main) tcgetattr error (%s)", strerror(errno));

	while ((ch = getopt(argc, argv, "df:i:r:t:")) != -1) {
		switch(ch) {
		case 'd':
			debug = 1;
			break;
		case 'f':
			if (strlen(optarg) != 1 || !isdigit((int)optarg[0]))
				ic_print_usage();
			i = atoi(optarg);
			if (i < 0 || i > 7)
				i = 0;
			opt->fac = facility[i];
			break;
		case 'h':
			ic_print_usage();
			break;
		case 'i':
			opt->ip = xstrdup(optarg);
			break;
		case 'p':
			opt->pidfile = xstrdup(optarg);
			break;
		case 'r':
			opt->dir = xstrdup(optarg);
			break;
		case 't':
			opt->timeout = (time_t)atoi(optarg);
			if (opt->timeout > (time_t)DEFAULT_INTERVAL)
				opt->timeout = DEFAULT_INTERVAL;
			break;
		default:
			ic_print_usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc)
		opt->ip = xstrdup(*argv);

	/*
	 * get interface address
	*/
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags     = AI_CANONNAME;
	hints.ai_family    = AF_INET;
	hints.ai_socktype  = SOCK_RAW;
	if (getaddrinfo(opt->ip, (char *)NULL, &hints, &src) != 0)
		ic_print_usage();
	opt->src    = src->ai_addr;
	opt->srclen = src->ai_addrlen;

	return opt;
}


/*-------------------------------------------------------------------------
 * put pid file
 *-------------------------------------------------------------------------
*/
void
ic_put_pidfile(OPT *opt) {
	FILE *fp;
	char buf[BUFSIZ];

	if (debug)
		return;

	if ((fp = fopen(opt->pidfile, "w")) == NULL)
		return;

#ifdef SOLARIS
	snprintf(buf, sizeof(buf), "%lu\n", getpid());
#else
	snprintf(buf, sizeof(buf), "%d\n", getpid());
#endif
	fputs(buf, fp);
	fclose(fp);

	return;
}


/*-------------------------------------------------------------------------
 * signal handler
 *-------------------------------------------------------------------------
*/
void
ic_ignore_sighup(void) {
	struct sigaction act, oact;

	act.sa_handler = SIG_IGN;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	if (sigaction(SIGHUP, &act, &oact) < 0)
		ic_plog(SDEB, "(main) can not set signal handler");

	return;
}

void
ic_sig_chld(int signo) {
	pid_t tmp_pid = -1;
	pid_t pid = -1;
	int status;
	proc_db *ptr;

	while ((tmp_pid = waitpid(-1, &status, WNOHANG)) > 0) {
		pid = tmp_pid;
		ic_plog(SDEB, "(main) child co-process %d terminated", pid);
	}

	/*
	 * reset session immediately
	*/
	if (pid > 0 && (ptr = ic_db_find_pid(pid)) != NULL)
		ic_reply(IC_EOT, ptr);

	return;
}

void
ic_catch_status(void) {
	struct sigaction act, oact;

	act.sa_handler = ic_sig_chld;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	if (sigaction(SIGCHLD, &act, &oact) < 0)
		ic_plog(SDEB, "(main) can not set signal handler");

	return;
}

/*-------------------------------------------------------------------------
 * switch daemon mode
 *-------------------------------------------------------------------------
*/
void
ic_go_daemon(OPT *opt) {
	int i;
	pid_t pid;

	if ((pid = xfork()) > 0) {
		exit(0);	/* first parent exit */
	}

	setsid();		/* get control terminal */
	ic_ignore_sighup();	/* ignore hang-up signal */
	ic_catch_status();	/* catch child process's status */

	if ((pid = xfork()) > 0) {
		exit(0);	/* second parent exit */
	}

	if (chdir(opt->dir) < 0) {
		exit(1);
	}

	for (i = 0; i < MAXFD; ++i) {
		close(i);	/* force to close all opened descriptors */
	}

	return;
}

/*-------------------------------------------------------------------------
 * database interface
 *
 *-------------------------------------------------------------------------
*/
static proc_db *Proc_db = NULL; /* base element */
static int nrecord = 0; /* total number of element */

/* insert flag */
#define IC_DB_REMOVE	0x01
#define IC_DB_UPDATE	0x02
/* not needed
#define IC_DB_INSERT	0x04
*/


/* local */
proc_db *
ic_db_make_list(void) {
	return xmalloc(sizeof(proc_db));
}

void
ic_db_lock(void) {
	return;
}

void
ic_db_unlock(void) {
	return;
}

/* public */
void
ic_db_cleanup(void) {
	proc_db *ptr, *tmptr;
	if (Proc_db == NULL) 
		return;

	ptr = Proc_db;
	do {
		tmptr = ptr->next;
		free(ptr);
		ptr = tmptr;
	} while (ptr);

	Proc_db = NULL;
	nrecord = 0;
	return;
}

int
ic_db_cleanup_old(time_t now, time_t sec) {
	int nfree;
	proc_db *ptr, *prev;
	if (Proc_db == NULL) 
		return (-1);

	nfree = 0;
	prev = Proc_db;
	ptr = prev->next;
	while (ptr) {
		if ((now - ptr->last) > sec) {
			proc_db *tmptr = ptr;
			ic_plog(SDEB, "(ic_db_cleanup_old) remove pid %d", ptr->id);
			ic_kill("ic_db_cleanup_old", ptr->shelldrv, SIGINT);
			prev->next = ptr->next;
			ptr = ptr->next;
			free(tmptr);
			++nfree;
			--nrecord;
		}
		else {
			prev = ptr;
			ptr = ptr->next;
		}
	}

	return (nfree);
}

void
ic_db_make(int rebuild) {
	if (rebuild)
		ic_db_cleanup();
	else if (Proc_db != NULL)
		return;

	Proc_db = xmalloc(sizeof(proc_db));

	return;
}

int
ic_db_nrecord(void) {
	return (nrecord);
}

proc_db *
ic_db_insert(ic_data *dg, int masterfd) {
	proc_db *new, *tmptr;
	ic_db_lock();
	new          = ic_db_make_list();
	new->client  = dg->iph.ip_src;
	new->local   = dg->iph.ip_dst;
	new->fd      = masterfd;
	new->id      = dg->icmph.id;
	new->create  = time(NULL);
	new->last    = time(NULL);
	strcpy(new->clientname, inet_ntoa(dg->iph.ip_src));

	tmptr = Proc_db->next;
	Proc_db->next = new;
	new->next = tmptr;

	ic_plog(SDEB, "(ic_db_insert) add entry pid %d", new->id);
	++nrecord;
	ic_db_unlock();
	return (new);
}

proc_db *
ic_db_remove(ic_data *dg) {
	proc_db *ptr, *prev;
	ic_db_lock();
	prev = Proc_db;
	for (ptr = Proc_db->next; ptr != NULL; ptr = ptr->next) {
		if (ptr->client.s_addr == dg->iph.ip_src.s_addr &&
		    ptr->id            == dg->icmph.id) {
			prev->next = ptr->next;
			free(ptr);
			--nrecord;
			break;
		}
		prev = ptr;
	}

	ic_db_unlock();
	return (NULL);
}

proc_db *
ic_db_find(ic_data *dg, int flag) {
	proc_db *ptr;

	if (Proc_db->next == NULL)
		return (NULL);

	for (ptr = Proc_db->next; ptr != NULL; ptr = ptr->next) {
		if (ptr->client.s_addr == dg->iph.ip_src.s_addr &&
		    ptr->id            == dg->icmph.id) {
			if (flag & IC_DB_REMOVE)
				/* need to improve for performance */
				return (ic_db_remove(dg));
			else {
				if (flag & IC_DB_UPDATE) {
					ic_db_lock();
					ptr->last = time(NULL);
					ic_db_unlock();
				}
				return (ptr);
			}
		}
	}

	return (NULL);
}

proc_db *
ic_db_find_pid(pid_t shelldrv_pid) {
	proc_db *ptr;

	if (Proc_db->next == NULL)
		return (NULL);

	for (ptr = Proc_db->next; ptr != NULL; ptr = ptr->next) {
		if (ptr->shelldrv == shelldrv_pid)
			return (ptr);
	}

	return (NULL);
}


/*-------------------------------------------------------------------------
 * shell driver
 *
 *-------------------------------------------------------------------------
*/

/*
 * ic_shell_driver has to terminate real shell, so that sends SIGTERM to it
 * when SIGINT is sent me by the parent.
*/

static char *pdrv = "ic_shell_driver";
static char *psh = "shell";

static pid_t ic_shelldrv_sigint     = 1; /* to terminate myself */
static pid_t ic_shelldrv_shell      = 0; /* real shell's pid */

void
ic_shelldrv_kill_child(void) {
	if (ic_shelldrv_shell == 0)
		return;
	ic_kill(pdrv, ic_shelldrv_shell, SIGTERM);
	ic_plog(SDEB, "(%s) sent signal to shell (%d)", pdrv, ic_shelldrv_shell);

	return;
}

void
ic_shelldrv_set_sigint(int signo) {
	ic_shelldrv_sigint = 0;
	return;
}

void
ic_shelldrv_catch_sigint(void) {
	struct sigaction act, oact;

	act.sa_handler = ic_shelldrv_set_sigint;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	if (sigaction(SIGINT, &act, &oact) < 0)
		ic_plog(SDEB, "(%s) can not set signal handler", pdrv);

	return;
}

void
ic_shelldrv_chld_stat(int signo) {
	pid_t pid;
	int status;

	while((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		ic_plog(SDEB, "(%s) child process %d terminated", pdrv, pid);
	}

	if (pid == ic_shelldrv_shell)
		ic_shelldrv_shell = 0;

	/* exit main loop in ic_shell_driver() */
	ic_shelldrv_set_sigint(0);

	return;
}

void
ic_shelldrv_catch_sigchld(void) {
	struct sigaction act, oact;

	act.sa_handler = ic_shelldrv_chld_stat;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	if (sigaction(SIGCHLD, &act, &oact) < 0)
		ic_plog(SDEB, "(%s) can not set signal handler", pdrv);

	return;
}

/*
 * ic_shell_driver main
*/

void
ic_set_icmp_echoreply(ic_data *pic, proc_db *pproc, u_char *ibuf, ssize_t sz) {
	u_short pid = pproc->id;
	u_short len = sz;

	ic_set_data(pic, IC_REPLY, IC_NORMAL, len, ibuf, sz);
	ic_set_header(pic, ICMP_ECHOREPLY, 0, pid, IC_TAG);

	return;
}

int
ic_responser(bufset *nbuf, proc_db *pproc) {
	ic_data dg;
	icmp_echo *picmph = &(dg.icmph);
	SA_IN addr;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = pproc->client.s_addr;

	while (nbuf->len > 0) {
		int iclen, send, retry;
		if (nbuf->len > IC_REALPAYLOAD) {
			iclen = IC_REALPAYLOAD;
			nbuf->len -= IC_REALPAYLOAD;
		}
		else {
			iclen = nbuf->len;
			nbuf->len = 0;
		}
		memset(&dg, 0, sizeof(dg));
		ic_set_icmp_echoreply(&dg, pproc, nbuf->buf, iclen);
		for (retry = 5; retry > 0; --retry) {
			send = sendto(sockout, (icmp_echo *)picmph, IC_DATASIZE, 0, (SA *)&addr, sizeof(addr));
			if (send < 0) {
				if (errno == ENOBUFS)
					continue;
				ic_plog(SINF, "(%s) unrecoverable error occured (%s)", pdrv, strerror(errno));
				return (-1);
			}
			else if (send == IC_DATASIZE)
				break;
		}
	}

	return (0);
}

int
ic_write_terminal(int shmaster, bufset *nbuf, pid_t shell) {
	switch (nbuf->buf[0]) {
	case IAC:
		switch (nbuf->buf[1]) {
#ifdef SOLARIS
		case IP:
			(void) ioctl(shmaster, TIOCSIGNAL, SIGINT);
			break;
		case SUSP:
			(void) ioctl(shmaster, TIOCSIGNAL, SIGTSTP);
			break;
		case ABORT:
			(void) ioctl(shmaster, TIOCSIGNAL, SIGQUIT);
			break;
		default:
			break;
		}
#else
		case IP:
			(void) ioctl(shmaster, TIOCSIG, (char *)SIGINT);
			break;
		case SUSP:
			(void) ioctl(shmaster, TIOCSIG, (char *)SIGTSTP);
			break;
		case ABORT:
			(void) ioctl(shmaster, TIOCSIG, (char *)SIGQUIT);
			break;
		default:
			break;
		}
#endif
		break;
	default:
		xwrite(shmaster, nbuf->buf, nbuf->len);
		break;
	}
	nbuf->len = 0;

	return (0);
}

int
ic_read_tty(int fd, bufset *nbuf) {
	int retry;
	int cc;
	u_char tempbuff[BUFSIZ];

	for (retry = 5; retry > 0; --retry) {
		cc = read(fd, tempbuff, nbuf->bufsz);
		if (cc < 0)
			if (errno == EINTR)
				continue;
			else
				return (0);
		else
			break;
	}

	if (cc > 0) {
		if ((nbuf->len + cc) > nbuf->bufsz) {
			nbuf->bufsz *= 2;
			nbuf->buf = xrealloc(nbuf->buf, nbuf->bufsz);
			ic_plog(SDEB, "(%s) expand bufset (%d)", pdrv, nbuf->bufsz);
		}
		memcpy(nbuf->buf + nbuf->len, tempbuff, cc);
		nbuf->len += cc;
	}

	return (cc);
}


void
ic_make_buf(bufset *term, bufset *net) {
	term->bufsz = net->bufsz = IC_REALPAYLOAD;
	term->len = net->len = 0;
	term->buf = xmalloc(term->bufsz);
	net->buf = xmalloc(net->bufsz);
	return;
}

char *
ic_login_path() {
#ifdef SOLARIS
	static char *login = "/bin/login";
#else
	static char *login = "/usr/bin/login";
#endif
	return (login);
}

#ifdef SOLARIS
void
ic_make_utmpx(char *pts) {
	struct utmpx ut;

	(void) memset((char *)&ut, 0, sizeof(ut));
	(void) strncpy(ut.ut_user, ".telnet", sizeof (ut.ut_user));
	(void) strncpy(ut.ut_line, pts, sizeof(ut.ut_line));
	ut.ut_pid = getpid();
	ut.ut_id[0] = 't';
	ut.ut_id[1] = (char)SC_WILDC;
	ut.ut_id[2] = (char)SC_WILDC;
	ut.ut_id[3] = (char)SC_WILDC;
	ut.ut_type = LOGIN_PROCESS;
	ut.ut_exit.e_termination = 0;
	ut.ut_exit.e_exit = 0;
	(void) time(&ut.ut_tv.tv_sec);
	if (makeutx(&ut) == NULL)
		ic_plog(SDEB, "(%s) makeutx fail", pdrv);

	return;
}
#endif

void
ic_shell_driver(int master, char *pts, char **envp, struct termios tt, struct winsize ws, proc_db proc) {
	const char *login = ic_login_path();
	int slave, shmaster, maxfd;
	int on = 1;
	struct termios rawtt;
	pid_t shellpid;
	char pts_shell[64]; /* save pts name, /dev/ptyXY */
	bufset termbuf, netbuf;
	fd_set rfd, wfd;

	/*
	 * get `pts' to communicate between icmpshd and ic_shell_driver,
	 * and close master
	*/
	if ((slave = ptys_open(master, pts)) < 0) {
		ic_plog(SDEB, "(%s) ptys_open failure", pdrv);
		return;
	}
	rawtt = tt;
	cfmakeraw(&rawtt);
	if (tcsetattr(slave, TCSANOW, &rawtt) < 0)
		ic_plog(SDEB, "(%s) tcsetattr failure (%s)", pdrv, strerror(errno));

	if (setsid() < 0) {
		ic_plog(SDEB, "(%s) setsid failure", pdrv);
		return;
	}

	if ((shmaster = ptym_open(pts_shell)) < 0) {
		ic_plog(SDEB, "(%s) ptym_open failure", pdrv);
		return;
	}
	(void) ioctl(shmaster, FIONBIO, (char *)&on);

	if ((shellpid = xfork()) == 0) {
		/* start real shell */
		int shslave;
		if (setsid() < 0)
			return;
		if ((shslave = ptys_open(shmaster, pts_shell)) < 0)
			return;
#ifndef SOLARIS
		/* ioctl(tty) not needed on SVR4
		 * slave becomes control terminal when process opens ptys
		*/
		if (ioctl(shslave, TIOCSCTTY, (char *)NULL) < 0)
			ic_plog(SDEB, "(%s) ioctl(tty) failure (%s)", psh, strerror(errno));
#endif
		tt.c_lflag |= ECHO;
		if (tcsetattr(shslave, TCSANOW, &tt) < 0)
			return;
		if (ioctl(shslave, TIOCSWINSZ, &ws) < 0)
			return;
		ic_plog(SDEB, "(%s) forked(%d)", psh, getpid());
		dup2(shslave, 0);
		dup2(shslave, 1);
		dup2(shslave, 2);
#ifdef SOLARIS
		ic_make_utmpx(pts_shell+6);
		execl(login, "login", "-p", "-h", proc.clientname, "-d", pts_shell, "--", getenv("USER"), 0);
#else
		execle(login, "login", "-h", proc.clientname, "-p", (char *)NULL, envp);
#endif
		ic_plog(SDEB, "(%s) fork login failure", psh);
		return;
	}
	else if (shellpid < 0) {
		ic_plog(SDEB, "(%s) fork failure", pdrv);
		return;
	}
		
	/*----------------------------------------------------
	 * ic_shell_driver main loop
	 *----------------------------------------------------
	*/

	ic_shelldrv_shell = shellpid;
	ic_shelldrv_catch_sigint();
	ic_shelldrv_catch_sigchld();

	ic_make_buf(&termbuf, &netbuf);
	MAXFD3(maxfd, shmaster, slave, sockout);
	FD_ZERO(&rfd);
	FD_ZERO(&wfd);

	while (ic_shelldrv_sigint) {
		int nfd;
		FD_ZERO(&wfd);
		if (termbuf.len)
			FD_SET(shmaster, &wfd);
		if (netbuf.len)
			FD_SET(sockout, &wfd);
		FD_SET(shmaster, &rfd);
		FD_SET(slave, &rfd);
		nfd = select(maxfd + 1, &rfd, &wfd, NULL, NULL);
		if (nfd < 0) {
			if (errno == EINTR)
				continue;
			ic_plog(SDEB, "(%s) select failure", pdrv);
			break;
		}
		/*
		 * response to client (write to network)
		*/
		if (nfd > 0 && netbuf.len > 0 && FD_ISSET(sockout, &wfd)) {
			(void) ic_responser(&netbuf, &proc);
		}
		/*
		 * write to real-shell
		*/
		if (nfd > 0 && termbuf.len > 0 && FD_ISSET(shmaster, &wfd)) {
			(void) ic_write_terminal(shmaster, &termbuf, shellpid);
		}
		/*
		 * read from shell
		*/
		if (nfd > 0 && FD_ISSET(shmaster, &rfd)) {
			(void) ic_read_tty(shmaster, &netbuf);
		}
		/*
		 * read from network and store in buffer
		*/
		if (nfd > 0 && FD_ISSET(slave, &rfd)) {
			(void) ic_read_tty(slave, &termbuf);
		}
	}

	ic_shelldrv_kill_child();

	ic_plog(SDEB, "(%s) exit", pdrv);
	exit (0);
}


/*-------------------------------------------------------------------------
 * request handler
 *    ic_reply()     common interface for ic_req_start & ic_req_quit
 *    ic_req_start() startup procedure
 *    ic_req_quit()  remove child process and clean up database
 *-------------------------------------------------------------------------
*/

int
ic_reply(u_char code, proc_db *proc) {
	int send;
	ic_data dg;
	icmp_echo *picmph = &(dg.icmph);
	SA_IN dst;

	memset(&dg, 0, sizeof(dg));
	ic_set_data(&dg, code, IC_NORMAL, 0, NULL, 0);
	ic_set_header(&dg, ICMP_ECHOREPLY, 0, proc->id, IC_TAG);

	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = proc->client.s_addr;
	for (;;) {
		send = sendto(sockout, (icmp_echo *)picmph, IC_DATASIZE, 0, (SA *)&dst, sizeof(dst));
		if (send == IC_DATASIZE)
			break;
		if (send < 0 && errno == ENOBUFS) {
			continue;
		}
		ic_plog(SDEB, "(ic_reply) sendto() failure");
		return (-1);
	}

	return (0);
}


/* IC_START */

int
ic_req_start(ic_data *pdg, char **envp, OPT *opt) {
	int master;
	int on = 1;
	char pts[64]; /* save pts name, /dev/ptyXY */
	proc_db *proc;
	pid_t shelldrv;

	if ((master = ptym_open(pts)) < 0) {
		ic_plog(SDEB, "(main) ptym_open failure");
		return (-1);
	}
	(void) ioctl(master, FIONBIO, (char *)&on);

	proc = ic_db_insert(pdg, master);

	if ((shelldrv = xfork()) == 0) {
		/* ic_shell_driver start */
		struct winsize ws;
		ic_get_winsz(&ws, &(pdg->data.ich.opt.nwinsz));
		ic_shell_driver(master, pts, envp, opt->origtt, ws, *proc);
	}
	else if (shelldrv < 0) {
		ic_db_remove(pdg);
		return (-1);
	}

	proc->shelldrv = shelldrv;
	ic_plog(SDEB, "(main) open master (%d) for shelldrv pid (%d)", master, shelldrv);
	ic_reply(IC_START_ACK, proc);

	return (0);
}


/* IC_REQ */
int
ic_req_req(ic_data *pdg) {
	u_char *ppay = (u_char *)&(pdg->data.payload[0]) + sizeof(ic_header);
	proc_db *proc;

	if ((proc = ic_db_find(pdg, IC_DB_UPDATE)) == NULL) {
		ic_plog(SDEB, "(main) no entry in proc_db");
		return (-1);
	}

	xwrite(proc->fd, ppay, pdg->data.ich.length);
	ic_plog(SDEB, "(main) sent through fd(%d), %d byte", proc->fd, pdg->data.ich.length);
	
	return (0);
}


/* IC_QUIT */
int
ic_req_quit(ic_data *pdg) {
	proc_db *proc;
	
	if ((proc = ic_db_find(pdg, 0)) == NULL) {
		ic_plog(SDEB, "(main) no entry in proc_db");
		return (-1);
	}

	/*
	 * terminate ic_shell_driver and its child(shell), see ic_shell_driver()
	 * in detail.
	*/
	ic_kill("main", proc->shelldrv, SIGINT);
	ic_reply(IC_QUIT_ACK, proc);

	/*
	 * remove entry from proc_db
	*/
	if ((proc = ic_db_remove(pdg)) == NULL)
		ic_plog(SDEB, "(main) removed entry");
	else
		ic_plog(SDEB, "(main) can not remove entry");

	return (0);
}


/*-------------------------------------------------------------------------
 * main
 *-------------------------------------------------------------------------
*/

/*
 * make new environment
*/
void
ic_env_make(void *envp) {
	extern char **environ;
	int i;
	int envn = 16;
	char **newenvp;

	newenvp = xmalloc(envn * sizeof(char *));
	for (i = 0; environ[i] != NULL; ++i) {
		if (i == envn) {
			envn *= 2;
			newenvp = xrealloc(newenvp, envn * sizeof(char *));
		}
		newenvp[i] = xstrdup(environ[i]);
	}
	if (getenv("TERM") == NULL) {
		newenvp[i] = xstrdup("TERM=vt100");
		++i;
	}

	if (i >= envn)
		newenvp = xrealloc(newenvp, (i + 1) * sizeof(char *));
	newenvp[i] = NULL;
	*((char **)envp) = (char *)newenvp;

	return;
}


/*
 * finger out whether incoming packet is icmpsh's format or not,
 * then return with value "1", which means true ("0" as opposite to "1")
*/
int
ic_is_icmpsh_server(ic_data *pdg) {
	if (pdg->iph.ip_hl != IC_IPHLWRS)
		return (0);

	if (pdg->icmph.seq   == IC_TAG &&
	   (pdg->icmph.type  == ICMP_ECHO ||
	    pdg->icmph.type  == ICMP_ECHOREPLY))
		ic_plog(SDEB, "(main) accept icmpsh packet");
	else
		return (0);

	ic_plog(SDEB, "(main)        src(%s), ",  inet_ntoa(pdg->iph.ip_src));
	ic_plog(SDEB, "(main)        dst(%s), ",  inet_ntoa(pdg->iph.ip_dst));
	ic_plog(SDEB, "(main)        type(%d), ", pdg->icmph.type);
	ic_plog(SDEB, "(main)        code(%d), ", pdg->icmph.code);
	ic_plog(SDEB, "(main)        id(%d), ",   pdg->icmph.id);
	ic_plog(SDEB, "(main)        seq(%d), ",  pdg->icmph.seq);
	ic_plog(SDEB, "(main)        type(%d)",   pdg->data.ich.type);

	return (1);
}

/*
 * open and configure socket
*/
int
ic_init_server(OPT *opt) {
	int on = 1;

	if ((sockin  = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		ic_plog(SDEB, "(main) socket failure in(%d)", sockin);
		return (-1);
	}
	if ((sockout = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		ic_plog(SDEB, "(main) socket failure out(%d)", sockout);
		return (-1);
	}

	if (ioctl(sockout, FIONBIO, (char *)&on) == -1) {
		ic_plog(SDEB, "(main) ioctl error sockout (%s)", strerror(errno));
		return (-1);
	}
	if (opt->src) {
		if (bind(sockin, opt->src, opt->srclen) != 0) {
			ic_plog(SDEB, "(main) bind error (%s)", strerror(errno));
			return (-1);
		}
	}

	return (0);
}


int
main(int argc, char **argv) {
	OPT *opt; /* command option */
	char **envp;
	
	opt = ic_option(argc, argv);
	openlog(program, LOG_PID, opt->fac);

	/* preparation */
	if (debug)
		ic_catch_status();
	else
		ic_go_daemon(opt);

	ic_put_pidfile(opt);
	ic_db_make(0);
	ic_env_make(&envp);

	/* socket */
	if (ic_init_server(opt) < 0)
		exit (1);

	/*
	 * main loop
	*/
	ic_plog(SINF, "(main) starting up");

	for(;;) {
		int nfd;
		ic_data dg; /* ip datagram */
		ssize_t n;
		SA_IN src;
		socklen_t srclen;

		ic_plog(SDEB, "(main) waiting(pid:%d)", getpid());

		if ((nfd = ic_select(sockin, opt->timeout)) == 0) {
			/* timeout */
			ic_plog(SINF, "(main) proc database -> %d", ic_db_nrecord());
			ic_db_cleanup_old(time(NULL), opt->timeout);
			continue;
		}
		memset(&dg, 0, sizeof(dg));
		n = recvfrom(sockin, (ic_data *)&dg, sizeof(dg), 0, (SA *)&src, &srclen);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			else {
				ic_plog(SDEB, "(main) error occued while reading, quit immediately");
				exit (1);
			}
		}
		else if (n == 0) {
			ic_plog(SDEB, "(main) no data read");
			continue;
		}
		else if (n != IC_IPSIZE) {
			ic_plog(SDEB, "(main) mismatch packet size");
			continue;
		}

		/* Is it icmpsh's packet ?? */
		ic_plog(SDEB, "(main) received packet (%d)", n);
		ic_recv_ntohs(&dg);
		if (ic_is_icmpsh_server(&dg) == 0)
			continue;
			
		/* execute command */
		switch (dg.data.ich.type) {
		case (IC_START):
			ic_plog(SDEB, "(main) req: IC_START");
			(void) ic_req_start(&dg, envp, opt);
			break;
		case (IC_REQ):
			ic_plog(SDEB, "(main) req: IC_REQ");
			(void) ic_req_req(&dg);
			break;
		case (IC_QUIT):
			ic_plog(SDEB, "(main) req: IC_QUIT");
			(void) ic_req_quit(&dg);
			break;
		default:
			ic_plog(SDEB, "(main) request not implemented");
		}
	}

	exit(0);
}

