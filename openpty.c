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

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#ifdef SOLARIS
 #include <stdlib.h>
 #include <stropts.h>
 #include <termios.h>
 #include <sys/ioctl.h>
#else /* BSD & Mac */
 #include <grp.h>
#endif


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


/********************************************
 * prototype
 ********************************************
*/
/* public */
int ptym_open(char *);
int ptys_open(int, char *);


/********************************************
 * open master and slave
 ********************************************
*/
#ifdef SOLARIS
int
ptym_open(char *pts) {
	char ptym[] = "/dev/ptmx";
	char *p;
	int master;

	if (pts == NULL)
		return (-1);

	if ((master = open(ptym, O_RDWR)) < 0)
		return (-1);

	if (grantpt(master) < 0)
		goto ptym_open_error;

	if (unlockpt(master) < 0)
		goto ptym_open_error;

	if ((p = ptsname(master)) == NULL)
		goto ptym_open_error;

	strcpy(pts, p);
	return (master);

ptym_open_error:
	close(master);
	return (-1);
}

int
ptys_open(int master, char *pts_name) {
	int slave;

	if ((slave = open(pts_name, O_RDWR)) < 0) {
		close(master);
		return (-1);
	}

	if (ioctl(slave, I_PUSH, "ptem") < 0)
		goto ptys_open_error;

	if (ioctl(slave, I_PUSH, "ldterm") < 0)
		goto ptys_open_error;

	if (ioctl(slave, I_PUSH, "ttcompat") < 0)
		goto ptys_open_error;

	return (slave);

ptys_open_error:
	close(master);
	close(slave);
	return (-1);
}
#else /* BSD & Mac */
int
ptym_open(char *pts_name) {
	int master;
	char *ptr1, *ptr2;

	if (pts_name == NULL)
		return (-1);

	strcpy(pts_name, "/dev/ptyXY");
	for (ptr1 = "pqrstuvwxyzPQRST"; *ptr1 != 0; ++ptr1) {
		pts_name[8] = *ptr1;
		for (ptr2 = "0123456789abcdef"; *ptr2 != 0; ++ptr2) {
			pts_name[9] = *ptr2;
			if ((master = open(pts_name, O_RDWR)) < 0) {
				if (errno == ENOENT)
					return (-1);
				else
					continue;
			}
			pts_name[5] = 't';
			return (master);
		}
	}

	return (-1);
}

int
ptys_open(int master, char *pts_name) {
	struct group *grptr;
	int gid, slave;

	if (master < 0 || pts_name == NULL)
		return (-1);

	if ((grptr = getgrnam("tty")) != NULL)
		gid = grptr->gr_gid;
	else
		gid = -1;

	chown(pts_name, getuid(), gid);
	chmod(pts_name, S_IRUSR|S_IWUSR|S_IWGRP);

	if ((slave = open(pts_name, O_RDWR)) < 0) {
		close(master);
		return (-1);
	}

	return (slave);
}
#endif

/* end of source */
