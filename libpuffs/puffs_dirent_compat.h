/*	$NetBSD: dirent.h,v 1.24 2008/03/15 19:02:49 christos Exp $	*/

/*-
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)dirent.h	8.3 (Berkeley) 8/10/94
 */

#ifndef _SYS_DIRENT_NETBSD_COMPAT_H_
#define _SYS_DIRENT_NETBSD_COMPAT_H_

#include <sys/dirent.h>

#define _DIRENT_ALIGN(dp) 3
/*
 * The _DIRENT_NAMEOFF macro returns the offset of the d_name field in
 * struct dirent
 */
#define _DIRENT_NAMEOFF(dp) \
    ((char *)(void *)&(dp)->d_name - (char *)(void *)dp)
/*
 * The _DIRENT_RECLEN macro gives the minimum record length which will hold
 * a name of size "namlen".  This requires the amount of space in struct dirent
 * without the d_name field, plus enough space for the name with a terminating
 * null byte (namlen+1), rounded up to a the appropriate byte boundary.
 */
#define _DIRENT_RECLEN(dp, namlen) \
    ((_DIRENT_NAMEOFF(dp) + (namlen) + 1 + _DIRENT_ALIGN(dp)) & \
    ~_DIRENT_ALIGN(dp))
/*
 * The _DIRENT_SIZE macro returns the minimum record length required for
 * name name stored in the current record.
 */
#define	_DIRENT_SIZE(dp) _DIRENT_RECLEN(dp, (dp)->d_namlen)
/*
 * The _DIRENT_NEXT macro advances to the next dirent record.
 */
#define _DIRENT_NEXT(dp) ((void *)((char *)(void *)(dp) + (dp)->d_reclen))
/*
 * The _DIRENT_MINSIZE returns the size of an empty (invalid) record.
 */
#define _DIRENT_MINSIZE(dp) _DIRENT_RECLEN(dp, 0)

#endif	/* !_SYS_DIRENT_NETBSD_COMPAT_H_ */
