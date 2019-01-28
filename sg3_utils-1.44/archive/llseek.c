/*
 * llseek.c -- stub calling the llseek system call
 *
 * Copyright (C) 1994 Remy Card.  This file may be redistributed
 * under the terms of the GNU Public License.
 *
 * This file is borrowed from the util-linux-2.11z tarball's implementation
 * of fdisk. It allows seeks to 64 bit offsets, if supported.
 * Changed "ext2_" prefix to "llse".
 */

#include "config.h"

#define _XOPEN_SOURCE 500
#define _GNU_SOURCE

#include <sys/types.h>

#include <errno.h>
#include <unistd.h>

#if defined(__GNUC__) || defined(HAS_LONG_LONG)
typedef int64_t       llse_loff_t;
#else
typedef long            llse_loff_t;
#endif

extern llse_loff_t llse_llseek (unsigned int, llse_loff_t, unsigned int);

#ifdef __linux__

#ifdef HAVE_LLSEEK
#include <syscall.h>

#else   /* HAVE_LLSEEK */

#if defined(__alpha__) || defined(__ia64__)  || defined(__s390x__) || defined (__x86_64__) || defined (__powerpc64__)

#define my_llseek lseek

#else
#include <linux/unistd.h>       /* for __NR__llseek */

static int _llseek (unsigned int, unsigned long,
                   unsigned long, llse_loff_t *, unsigned int);

#ifdef __NR__llseek

static _syscall5(int,_llseek,unsigned int,fd,unsigned long,offset_high,
                 unsigned long, offset_low,llse_loff_t *,result,
                 unsigned int, origin)

#else

/* no __NR__llseek on compilation machine - might give it explicitly */
static int _llseek (unsigned int fd, unsigned long oh,
                    unsigned long ol, llse_loff_t *result,
                    unsigned int origin) {
        errno = ENOSYS;
        return -1;
}

#endif

static llse_loff_t my_llseek (unsigned int fd, llse_loff_t offset,
                unsigned int origin)
{
        llse_loff_t result;
        int retval;

#ifdef HAVE_LSEEK64
        return lseek64 (fd, offset, origin);
#else
        retval = _llseek (fd, ((uint64_t) offset) >> 32,
                        ((uint64_t) offset) & 0xffffffff,
                        &result, origin);
        return (retval == -1 ? (llse_loff_t) retval : result);
#endif
}

#endif /* __alpha__ */

#endif  /* HAVE_LLSEEK */

llse_loff_t llse_llseek (unsigned int fd, llse_loff_t offset,
                         unsigned int origin)
{
        llse_loff_t result;
        static int do_compat = 0;

        if (!do_compat) {
                result = my_llseek (fd, offset, origin);
                if (!(result == -1 && errno == ENOSYS))
                        return result;

                /*
                 * Just in case this code runs on top of an old kernel
                 * which does not support the llseek system call
                 */
                do_compat = 1;
                /*
                 * Now try ordinary lseek.
                 */
        }

        if ((sizeof(off_t) >= sizeof(llse_loff_t)) ||
            (offset < ((llse_loff_t) 1 << ((sizeof(off_t)*8) -1))))
                return lseek(fd, (off_t) offset, origin);

        errno = EINVAL;
        return -1;
}

#else /* !linux */

llse_loff_t llse_llseek (unsigned int fd, llse_loff_t offset,
                         unsigned int origin)
{
        if ((sizeof(off_t) < sizeof(llse_loff_t)) &&
            (offset >= ((llse_loff_t) 1 << ((sizeof(off_t)*8) -1)))) {
                errno = EINVAL;
                return -1;
        }
        return lseek (fd, (off_t) offset, origin);
}

#endif  /* linux */

