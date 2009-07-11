/*
 * Based on:
 *      src/sbin/sysctl/sysctl.c
 *
 * Copyright (c) 1993
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
 * 4. Neither the name of the University nor the names of its contributors
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
 */
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Sysctl.h"


/*{
typedef struct SysctlType_ SysctlType;

typedef void * (*Sysctl_Get)(const char *name, size_t *size);
typedef int (*Sysctl_GetInt)(const char *name);

struct SysctlType_ {
    Sysctl_Get    get;
    Sysctl_GetInt getInt;
};
}*/


static int name2oid(char *name, int *oidp);
static int oidfmt(int *oid, int len, char *fmt, size_t fmtsiz, u_int *kind);


static void * get(const char *name, size_t *size) {
    int nlen, i, oid[CTL_MAXNAME];
    size_t len;
    u_int kind;
    char *data, key[BUFSIZ];

    /* check args */
    if (name == NULL || *name == '\0')
        assert(("NULL or empty sysctl key", 0));
    if (size != NULL)
        *size = 0;

    if (strlcpy(key, name, sizeof(key)) >= sizeof(key))
        assert(("sysctl key too long", 0));

    /* get the oid */
    nlen = name2oid(key, oid);
    if (nlen < 0)
        assert(("unknown iod", 0));

    /* get the type */
    if (oidfmt(oid, nlen, NULL, 0, &kind) != 0)
        assert(("couldn't find format/kind of oid", 0));

    /* check the type */
    if ((kind & CTLTYPE) == CTLTYPE_NODE)
        assert(("can't handle CTLTYPE_NODE", 0));

    /* find an estimate of how much we need for this var */
    len = 0;
    (void)sysctl(oid, nlen, NULL, &len, NULL, 0);
    len += len; /* we want to be sure :-) */

    /* alloc */
    data = malloc(len + 1);
    if (data == NULL)
        assert(("malloc(3) failed", 0));

    /* call sysctl */
    i = sysctl(oid, nlen, data, &len, NULL, 0);
    if (i || !len)
        assert(("sysctl(3) failed", 0));

    /* fix/set the returned values */
    data[len] = '\0';
    if (size != NULL)
        *size = len;

    /* and that's it! */
    return (data);
}


static int getInt(const char *name) {
    int i, *data;
    size_t size;

    data = get(name, &size);
    if (size != sizeof(int))
        assert(("bad size for int", 0));

    i = *data;
    free(data);
    return (i);
}


/* stuff stolen from sysctl(8) */

/*
 * These functions uses a presently undocumented interface to the kernel
 * to walk the tree and get the type so it can print the value.
 * This interface is under work and consideration, and should probably
 * be killed with a big axe by the first person who can find the time.
 * (be aware though, that the proper interface isn't as obvious as it
 * may seem, there are various conflicting requirements.
 */

static int name2oid(char *name, int *oidp) {
    int oid[2];
    int i;
    size_t j;

    oid[0] = 0;
    oid[1] = 3;

    j = CTL_MAXNAME * sizeof(int);
    i = sysctl(oid, 2, oidp, &j, name, strlen(name));
    if (i < 0)
        return (i);
    j /= sizeof(int);
    return (j);
}


static int oidfmt(int *oid, int len, char *fmt, size_t fmtsiz, u_int *kind) {
    int qoid[CTL_MAXNAME+2];
    u_char buf[BUFSIZ];
    int i;
    size_t j;

    qoid[0] = 0;
    qoid[1] = 4;
    memcpy(qoid + 2, oid, len * sizeof(int));

    j = sizeof(buf);
    i = sysctl(qoid, len + 2, buf, &j, 0, 0);
    if (i)
        return (1);

    if (kind)
        *kind = *(u_int *)buf;

    if (fmt) {
        if (strlcpy(fmt, (char *)(buf + sizeof(u_int)), fmtsiz) >= fmtsiz)
            return (1);
    }
    return (0);
}


SysctlType Sysctl = {
   .get = get,
   .getInt = getInt,
};
