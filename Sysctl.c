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
#include <sys/user.h>
#include <sys/vmmeter.h>
#include <vm/vm_param.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Sysctl.h"


/*{
typedef struct SysctlType_ SysctlType;


typedef void * (*Sysctl_Get)(const char *name, size_t *size);

typedef int (*Sysctl_GetInt)(const char *name);
typedef unsigned int (*Sysctl_GetUnsignedInt)(const char *name);
typedef unsigned long (*Sysctl_GetUnsignedLong)(const char *name);
typedef struct xswdev * (*Sysctl_GetSwap)(const int swapdevid);
typedef size_t (*Sysctl_getAllProc)(struct kinfo_proc **data);


struct SysctlType_ {
    Sysctl_Get get;

    Sysctl_GetInt geti;
    Sysctl_GetUnsignedInt getui;
    Sysctl_GetUnsignedLong getul;

    Sysctl_GetSwap getswap;
    Sysctl_getAllProc getallproc;
};
}*/


static int name2oid(char *name, int *oidp);
static int oidfmt(int *oid, int len, char *fmt, size_t fmtsiz, u_int *kind);


static void * getbyoid(int *oid, int oidlen, size_t *size) {
    int i;
    char *data;
    size_t len;

    /* find an estimate of how much we need for this var */
    len = 0;
    (void)sysctl(oid, oidlen, NULL, &len, NULL, 0);
    len += len; /* we want to be sure :-) */

    /* alloc */
    data = malloc(len + 1);
    if (data == NULL)
        assert(("malloc(3) failed", 0));

    /* call sysctl */
    i = sysctl(oid, oidlen, data, &len, NULL, 0);
    if (i || !len)
        assert(("sysctl(3) failed", 0));

    /* fix/set the returned values */
    data[len] = '\0';
    if (size != NULL)
        *size = len;

    /* and that's it! */
    return (data);
}


static void * get(const char *name, size_t *size) {
    int oidlen, oid[CTL_MAXNAME];
    char key[BUFSIZ];

    /* check args */
    if (name == NULL || *name == '\0')
        assert(("NULL or empty sysctl key", 0));
    if (size != NULL)
        *size = 0;

    if (strlcpy(key, name, sizeof(key)) >= sizeof(key))
        assert(("sysctl key too long", 0));

    /* get the oid */
    oidlen = name2oid(key, oid);
    if (oidlen < 0)
        assert(("unknown iod", 0));

#if 0
    /* get the type */
    if (oidfmt(oid, oidlen, NULL, 0, &kind) != 0)
        assert(("couldn't find format/kind of oid", 0));

    /* check the type */
    if ((kind & CTLTYPE) == CTLTYPE_NODE)
        assert(("can't handle CTLTYPE_NODE", 0));
#endif

    return (getbyoid(oid, oidlen, size));
}


static int geti(const char *name) {
    int i, *data;
    size_t size;

    data = get(name, &size);
    if (size != sizeof(int))
        assert(("bad size for int", 0));

    i = *data;
    free(data);
    return (i);
}


static unsigned int getui(const char *name) {
    unsigned int i, *data;
    size_t size;

    data = get(name, &size);
    if (size != sizeof(unsigned int))
        assert(("bad size for unsigned int", 0));

    i = *data;
    free(data);
    return (i);
}


static unsigned long getul(const char *name) {
    unsigned long lu, *data;
    size_t size;

    data = get(name, &size);
    if (size != sizeof(unsigned long))
        assert(("bad size for unsigned long", 0));

    lu = *data;
    free(data);
    return (lu);
}


static struct xswdev * getswap(const int swapdevid) {
    struct xswdev *xsd;
    int oid[3];
    size_t size = 0, oidsize = 2;

    if (sysctlnametomib("vm.swap_info", oid, &oidsize) == -1)
        assert(("sysctlnametomib failed for vm.swap_info", 0));
    if (oidsize != 2)
        assert(("wrong size for oid vm.swap_info", 0));

    oid[oidsize] = swapdevid;
    xsd = getbyoid(oid, oidsize + 1, &size);

    if (size != sizeof(struct xswdev))
        assert(("wrong size for vm.swap_info", 0));
    if (xsd->xsw_version != XSWDEV_VERSION)
        assert(("wrong version for vm.swap_info", 0));

    return (xsd);
}


static size_t getallproc(struct kinfo_proc **kippptr) {
    size_t size, count;
    struct kinfo_proc *kipp;

    int oid[3] = {
        CTL_KERN, KERN_PROC, KERN_PROC_PROC
    };
    kipp = getbyoid(oid, 3, &size);

    if (size % sizeof(struct kinfo_proc) != 0)
        assert(("wrong size for kern.proc.all", 0));
    if (kipp->ki_structsize != sizeof(struct kinfo_proc))
        assert(("wrong size for kern.proc.all structure", 0));

    if (kippptr == NULL)
        free(kipp);
    else
        *kippptr = kipp;

    count = size / sizeof(struct kinfo_proc);
    return (count);
}


SysctlType Sysctl = {
    .get      = get,

    .geti    = geti,
    .getui   = getui,
    .getul   = getul,

    .getswap    = getswap,
    .getallproc = getallproc,
};


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

