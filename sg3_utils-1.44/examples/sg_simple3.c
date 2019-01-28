#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_lib.h"
#include "sg_io_linux.h"

/* This is a simple program executing a SCSI INQUIRY command and a
   TEST UNIT READY command using the SCSI generic (sg) driver.
   There is another variant of this program called "sg_simple1".
   This variant demonstrates using the scatter gather facility in
   the sg_io_hdr interface to break an INQUIRY response into its
   component parts.

*  Copyright (C) 1999-2016 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   Invocation: sg_simple3 [-x] <sg_device>

   Version 03.59 (20160528)

6 byte INQUIRY command:
[0x12][   |lu][pg cde][res   ][al len][cntrl ]

6 byte TEST UNIT READY command:
[0x00][   |lu][res   ][res   ][res   ][res   ]

*/

#define INQ_REPLY_BASE_LEN 8
#define INQ_REPLY_VID_LEN 8
#define INQ_REPLY_PID_LEN 16
#define INQ_REPLY_PREV_LEN 4
#define INQ_REPLY_IOVEC_COUNT 4
#define INQ_CMD_LEN 6
#define TUR_CMD_LEN 6

#define EBUFF_SZ 256

int main(int argc, char * argv[])
{
    int sg_fd, k, ok;
    unsigned char inq_cdb[INQ_CMD_LEN] = {0x12, 0, 0, 0,
                    INQ_REPLY_BASE_LEN + INQ_REPLY_VID_LEN +
                    INQ_REPLY_PID_LEN + INQ_REPLY_PREV_LEN, 0};
    unsigned char tur_cdb[TUR_CMD_LEN] = {0x00, 0, 0, 0, 0, 0};
    sg_iovec_t iovec[INQ_REPLY_IOVEC_COUNT];
    unsigned char inqBaseBuff[INQ_REPLY_BASE_LEN];
    char inqVidBuff[INQ_REPLY_VID_LEN];
    char inqPidBuff[INQ_REPLY_PID_LEN];
    char inqPRevBuff[INQ_REPLY_PREV_LEN];
    sg_io_hdr_t io_hdr;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char sense_buffer[32];
    int do_extra = 0;

    for (k = 1; k < argc; ++k) {
        if (0 == memcmp("-x", argv[k], 2))
            do_extra = 1;
        else if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        }
        else if (0 == file_name)
            file_name = argv[k];
        else {
            printf("too many arguments\n");
            file_name = 0;
            break;
        }
    }
    if (0 == file_name) {
        printf("Usage: 'sg_simple3 [-x] <sg_device>'\n");
        return 1;
    }

    /* N.B. An access mode of O_RDWR is required for some SCSI commands */
    if ((sg_fd = open(file_name, O_RDONLY)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "sg_simple3: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    /* Just to be safe, check we have a new sg device by trying an ioctl */
    if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000)) {
        printf("sg_simple3: %s doesn't seem to be an new sg device\n",
               file_name);
        close(sg_fd);
        return 1;
    }

    /* Prepare INQUIRY command */
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inq_cdb);
    io_hdr.iovec_count = INQ_REPLY_IOVEC_COUNT;
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = INQ_REPLY_BASE_LEN + INQ_REPLY_VID_LEN +
                       INQ_REPLY_PID_LEN + INQ_REPLY_PREV_LEN;
    iovec[0].iov_base = inqBaseBuff;
    iovec[0].iov_len = INQ_REPLY_BASE_LEN;
    iovec[1].iov_base = inqVidBuff;
    iovec[1].iov_len = INQ_REPLY_VID_LEN;
    iovec[2].iov_base = inqPidBuff;
    iovec[2].iov_len = INQ_REPLY_PID_LEN;
    iovec[3].iov_base = inqPRevBuff;
    iovec[3].iov_len = INQ_REPLY_PREV_LEN;
    io_hdr.dxferp = iovec;
    io_hdr.cmdp = inq_cdb;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
    /* io_hdr.flags = 0; */     /* take defaults: indirect IO, etc */
    /* io_hdr.pack_id = 0; */
    /* io_hdr.usr_ptr = NULL; */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg_simple3: Inquiry SG_IO ioctl error");
        close(sg_fd);
        return 1;
    }

    /* now for the error processing */
    ok = 0;
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        ok = 1;
        break;
    case SG_LIB_CAT_RECOVERED:
        printf("Recovered error on INQUIRY, continuing\n");
        ok = 1;
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("INQUIRY command error", &io_hdr, 1);
        break;
    }

    if (ok) { /* output result if it is available */
        char * p = (char *)inqBaseBuff;
        int f = (int)*(p + 7);
        printf("Some of the INQUIRY command's results:\n");
        printf("  %.8s  %.16s  %.4s  ", inqVidBuff, inqPidBuff, inqPRevBuff);
        printf("[wide=%d sync=%d cmdque=%d sftre=%d]\n",
               !!(f & 0x20), !!(f & 0x10), !!(f & 2), !!(f & 1));
        /* Extra info, not necessary to look at */
        if (do_extra)
            printf("INQUIRY duration=%u millisecs, resid=%d, msg_status=%d\n",
                   io_hdr.duration, io_hdr.resid, (int)io_hdr.msg_status);
    }


    /* Prepare TEST UNIT READY command */
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(tur_cdb);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_NONE;
    io_hdr.cmdp = tur_cdb;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg_simple3: Test Unit Ready SG_IO ioctl error");
        close(sg_fd);
        return 1;
    }

    /* now for the error processing */
    ok = 0;
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        ok = 1;
        break;
    case SG_LIB_CAT_RECOVERED:
        printf("Recovered error on Test Unit Ready, continuing\n");
        ok = 1;
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("Test Unit Ready command error", &io_hdr, 1);
        break;
    }

    if (ok)
        printf("Test Unit Ready successful so unit is ready!\n");
    else
        printf("Test Unit Ready failed so unit may _not_ be ready!\n");

    if (do_extra)
        printf("TEST UNIT READY duration=%u millisecs, resid=%d, "
                "msg_status=%d\n", io_hdr.duration, io_hdr.resid,
                (int)io_hdr.msg_status);

    close(sg_fd);
    return 0;
}
