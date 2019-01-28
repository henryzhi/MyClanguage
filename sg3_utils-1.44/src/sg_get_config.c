/*
 * Copyright (c) 2004-2018 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_mmc.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 * This program outputs information provided by a SCSI "Get Configuration"
   command [0x46] which is only defined for CD/DVDs (in MMC-2,3,4,5,6).

*/

static const char * version_str = "0.49 20180626";    /* mmc6r02 */

#define MX_ALLOC_LEN 8192
#define NAME_BUFF_SZ 64

#define ME "sg_get_config: "


static uint8_t resp_buffer[MX_ALLOC_LEN];

static struct option long_options[] = {
        {"brief", no_argument, 0, 'b'},
        {"current", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"inner-hex", no_argument, 0, 'i'},
        {"list", no_argument, 0, 'l'},
        {"raw", no_argument, 0, 'R'},
        {"readonly", no_argument, 0, 'q'},
        {"rt", required_argument, 0, 'r'},
        {"starting", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage:  sg_get_config [--brief] [--current] [--help] [--hex] "
            "[--inner-hex]\n"
            "                      [--list] [--raw] [--readonly] [--rt=RT]\n"
            "                      [--starting=FC] [--verbose] [--version] "
            "DEVICE\n"
            "  where:\n"
            "    --brief|-b       only give feature names of DEVICE "
            "(don't decode)\n"
            "    --current|-c     equivalent to '--rt=1' (show "
            "current)\n"
            "    --help|-h        print usage message then exit\n"
            "    --hex|-H         output response in hex\n"
            "    --inner-hex|-i    decode to feature name, then output "
            "features in hex\n"
            "    --list|-l        list all known features + profiles "
            "(ignore DEVICE)\n"
            "    --raw|-R         output in binary (to stdout)\n"
            "    --readonly|-q    open DEVICE read-only (def: open it "
            "read-write)\n"
            "    --rt=RT|-r RT    default value is 0\n"
            "                     0 -> all feature descriptors (regardless "
            "of currency)\n"
            "                     1 -> all current feature descriptors\n"
            "                     2 -> only feature descriptor matching "
            "'starting'\n"
            "    --starting=FC|-s FC    starting from feature "
            "code (FC) value\n"
            "    --verbose|-v     verbose\n"
            "    --version|-V     output version string\n\n"
            "Get configuration information for MMC drive and/or media\n");
}

struct val_desc_t {
        int val;
        const char * desc;
};

static struct val_desc_t profile_desc_arr[] = {
        {0x0, "No current profile"},
        {0x1, "Non-removable disk (obs)"},
        {0x2, "Removable disk"},
        {0x3, "Magneto optical erasable"},
        {0x4, "Optical write once"},
        {0x5, "AS-MO"},
        {0x8, "CD-ROM"},
        {0x9, "CD-R"},
        {0xa, "CD-RW"},
        {0x10, "DVD-ROM"},
        {0x11, "DVD-R sequential recording"},
        {0x12, "DVD-RAM"},
        {0x13, "DVD-RW restricted overwrite"},
        {0x14, "DVD-RW sequential recording"},
        {0x15, "DVD-R dual layer sequental recording"},
        {0x16, "DVD-R dual layer jump recording"},
        {0x17, "DVD-RW dual layer"},
        {0x18, "DVD-Download disc recording"},
        {0x1a, "DVD+RW"},
        {0x1b, "DVD+R"},
        {0x20, "DDCD-ROM"},
        {0x21, "DDCD-R"},
        {0x22, "DDCD-RW"},
        {0x2a, "DVD+RW dual layer"},
        {0x2b, "DVD+R dual layer"},
        {0x40, "BD-ROM"},
        {0x41, "BD-R SRM"},
        {0x42, "BD-R RRM"},
        {0x43, "BD-RE"},
        {0x50, "HD DVD-ROM"},
        {0x51, "HD DVD-R"},
        {0x52, "HD DVD-RAM"},
        {0x53, "HD DVD-RW"},
        {0x58, "HD DVD-R dual layer"},
        {0x5a, "HD DVD-RW dual layer"},
        {0xffff, "Non-conforming profile"},
        {-1, NULL},
};

static const char *
get_profile_str(int profile_num, char * buff)
{
    const struct val_desc_t * pdp;

    for (pdp = profile_desc_arr; pdp->desc; ++pdp) {
        if (pdp->val == profile_num) {
            strcpy(buff, pdp->desc);
            return buff;
        }
    }
    snprintf(buff, 64, "0x%x", profile_num);
    return buff;
}

static struct val_desc_t feature_desc_arr[] = {
        {0x0, "Profile list"},
        {0x1, "Core"},
        {0x2, "Morphing"},
        {0x3, "Removable media"},
        {0x4, "Write Protect"},
        {0x10, "Random readable"},
        {0x1d, "Multi-read"},
        {0x1e, "CD read"},
        {0x1f, "DVD read"},
        {0x20, "Random writable"},
        {0x21, "Incremental streaming writable"},
        {0x22, "Sector erasable"},
        {0x23, "Formattable"},
        {0x24, "Hardware defect management"},
        {0x25, "Write once"},
        {0x26, "Restricted overwrite"},
        {0x27, "CD-RW CAV write"},
        {0x28, "MRW"},          /* Mount Rainier reWritable */
        {0x29, "Enhanced defect reporting"},
        {0x2a, "DVD+RW"},
        {0x2b, "DVD+R"},
        {0x2c, "Rigid restricted overwrite"},
        {0x2d, "CD track-at-once"},
        {0x2e, "CD mastering (session at once)"},
        {0x2f, "DVD-R/-RW write"},
        {0x30, "Double density CD read"},
        {0x31, "Double density CD-R write"},
        {0x32, "Double density CD-RW write"},
        {0x33, "Layer jump recording"},
        {0x34, "LJ rigid restricted oberwrite"},
        {0x35, "Stop long operation"},
        {0x37, "CD-RW media write support"},
        {0x38, "BD-R POW"},
        {0x3a, "DVD+RW dual layer"},
        {0x3b, "DVD+R dual layer"},
        {0x40, "BD read"},
        {0x41, "BD write"},
        {0x42, "TSR (timely safe recording)"},
        {0x50, "HD DVD read"},
        {0x51, "HD DVD write"},
        {0x52, "HD DVD-RW fragment recording"},
        {0x80, "Hybrid disc"},
        {0x100, "Power management"},
        {0x101, "SMART"},
        {0x102, "Embedded changer"},
        {0x103, "CD audio external play"},
        {0x104, "Microcode upgrade"},
        {0x105, "Timeout"},
        {0x106, "DVD CSS"},
        {0x107, "Real time streaming"},
        {0x108, "Drive serial number"},
        {0x109, "Media serial number"},
        {0x10a, "Disc control blocks"},
        {0x10b, "DVD CPRM"},
        {0x10c, "Firmware information"},
        {0x10d, "AACS"},
        {0x10e, "DVD CSS managed recording"},
        {0x110, "VCPS"},
        {0x113, "SecurDisc"},
        {0x120, "BD CPS"},
        {0x142, "OSSC"},
};

static const char *
get_feature_str(int feature_num, char * buff)
{
    int k, num;

    num = SG_ARRAY_SIZE(feature_desc_arr);
    for (k = 0; k < num; ++k) {
        if (feature_desc_arr[k].val == feature_num) {
            strcpy(buff, feature_desc_arr[k].desc);
            return buff;
        }
    }
    snprintf(buff, 64, "0x%x", feature_num);
    return buff;
}

static void
dStrRaw(const char * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

static void
decode_feature(int feature, uint8_t * bp, int len)
{
    int k, num, n, profile;
    char buff[128];
    const char * cp;

    switch (feature) {
    case 0:     /* Profile list */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 2), !!(bp[2] & 1),
               feature);
        printf("    available profiles [more recent typically higher "
               "in list]:\n");
        for (k = 4; k < len; k += 4) {
            profile = sg_get_unaligned_be16(bp + k);
            printf("      profile: %s , currentP=%d\n",
                   get_profile_str(profile, buff), !!(bp[k + 2] & 1));
        }
        break;
    case 1:     /* Core */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 2), !!(bp[2] & 1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        num = sg_get_unaligned_be32(bp + 4);
        switch (num) {
        case 0: cp = "unspecified"; break;
        case 1: cp = "SCSI family"; break;
        case 2: cp = "ATAPI"; break;
        case 3: cp = "IEEE 1394 - 1995"; break;
        case 4: cp = "IEEE 1394A"; break;
        case 5: cp = "Fibre channel"; break;
        case 6: cp = "IEEE 1394B"; break;
        case 7: cp = "Serial ATAPI"; break;
        case 8: cp = "USB (both 1 and 2)"; break;
        case 0xffff: cp = "vendor unique"; break;
        default:
            snprintf(buff, sizeof(buff), "[0x%x]", num);
            cp = buff;
            break;
        }
        printf("      Physical interface standard: %s", cp);
        if (len > 8)
            printf(", INQ2=%d, DBE=%d\n", !!(bp[8] & 2), !!(bp[8] & 1));
        else
            printf("\n");
        break;
    case 2:     /* Morphing */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 2), !!(bp[2] & 1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      OCEvent=%d, ASYNC=%d\n", !!(bp[4] & 2), !!(bp[4] & 1));
        break;
    case 3:     /* Removable medium */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 2), !!(bp[2] & 1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        num = (bp[4] >> 5) & 0x7;
        switch (num) {
        case 0: cp = "Caddy/slot type"; break;
        case 1: cp = "Tray type"; break;
        case 2: cp = "Pop-up type"; break;
        case 4: cp = "Embedded changer with individually changeable discs";
            break;
        case 5: cp = "Embedded changer using a magazine"; break;
        default:
            snprintf(buff, sizeof(buff), "[0x%x]", num);
            cp = buff;
            break;
        }
        printf("      Loading mechanism: %s\n", cp);
        printf("      Load=%d, Eject=%d, Prevent jumper=%d, Lock=%d\n",
               !!(bp[4] & 0x10), !!(bp[4] & 0x8), !!(bp[4] & 0x4),
               !!(bp[4] & 0x1));
        break;
    case 4:     /* Write protect */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      DWP=%d, WDCB=%d, SPWP=%d, SSWPP=%d\n", !!(bp[4] & 0x8),
               !!(bp[4] & 0x4), !!(bp[4] & 0x2), !!(bp[4] & 0x1));
        break;
    case 0x10:     /* Random readable */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 12) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        num = sg_get_unaligned_be32(bp + 4);
        printf("      Logical block size=0x%x, blocking=0x%x, PP=%d\n",
               num, sg_get_unaligned_be16(bp + 8), !!(bp[10] & 0x1));
        break;
    case 0x1d:     /* Multi-read */
    case 0x22:     /* Sector erasable */
    case 0x26:     /* Restricted overwrite */
    case 0x27:     /* CDRW CAV write */
    case 0x35:     /* Stop long operation */
    case 0x38:     /* BD-R pseudo-overwrite (POW) */
    case 0x42:     /* TSR (timely safe recording) */
    case 0x100:    /* Power management */
    case 0x109:    /* Media serial number */
    case 0x110:    /* VCPS */
    case 0x113:    /* SecurDisc */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        break;
    case 0x1e:     /* CD read */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      DAP=%d, C2 flags=%d, CD-Text=%d\n", !!(bp[4] & 0x80),
               !!(bp[4] & 0x2), !!(bp[4] & 0x1));
        break;
    case 0x1f:     /* DVD read */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len > 7)
            printf("      MULTI110=%d, Dual-RW=%d, Dual-R=%d\n",
                   !!(bp[4] & 0x1), !!(bp[6] & 0x2), !!(bp[6] & 0x1));
        break;
    case 0x20:     /* Random writable */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 16) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        num = sg_get_unaligned_be32(bp + 4);
        n = sg_get_unaligned_be32(bp + 8);
        printf("      Last lba=0x%x, Logical block size=0x%x, blocking=0x%x,"
               " PP=%d\n", num, n, sg_get_unaligned_be16(bp + 12),
               !!(bp[14] & 0x1));
        break;
    case 0x21:     /* Incremental streaming writable */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Data block types supported=0x%x, TRIO=%d, ARSV=%d, "
               "BUF=%d\n", sg_get_unaligned_be16(bp + 4), !!(bp[6] & 0x4),
               !!(bp[6] & 0x2), !!(bp[6] & 0x1));
        num = bp[7];
        printf("      Number of link sizes=%d\n", num);
        for (k = 0; k < num; ++k)
            printf("        %d\n", bp[8 + k]);
        break;
    /* case 0x22:     Sector erasable -> see 0x1d entry */
    case 0x23:     /* Formattable */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len > 4)
            printf("      BD-RE: RENoSA=%d, Expand=%d, QCert=%d, Cert=%d, "
                   "FRF=%d\n", !!(bp[4] & 0x8), !!(bp[4] & 0x4),
                   !!(bp[4] & 0x2), !!(bp[4] & 0x1), !!(bp[5] & 0x80));
        if (len > 8)
            printf("      BD-R: RRM=%d\n", !!(bp[8] & 0x1));
        break;
    case 0x24:     /* Hardware defect management */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len > 4)
            printf("      SSA=%d\n", !!(bp[4] & 0x80));
        break;
    case 0x25:     /* Write once */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 12) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        num = sg_get_unaligned_be16(bp + 4);
        printf("      Logical block size=0x%x, blocking=0x%x, PP=%d\n",
               num, sg_get_unaligned_be16(bp + 8), !!(bp[10] & 0x1));
        break;
    /* case 0x26:     Restricted overwrite -> see 0x1d entry */
    /* case 0x27:     CDRW CAV write -> see 0x1d entry */
    case 0x28:     /* MRW  (Mount Rainier reWriteable) */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len > 4)
            printf("      DVD+Write=%d, DVD+Read=%d, Write=%d\n",
                   !!(bp[4] & 0x4), !!(bp[4] & 0x2), !!(bp[4] & 0x1));
        break;
    case 0x29:     /* Enhanced defect reporting */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      DRT-DM=%d, number of DBI cache zones=0x%x, number of "
               "entries=0x%x\n", !!(bp[4] & 0x1), bp[5],
               sg_get_unaligned_be16(bp + 6));
        break;
    case 0x2a:     /* DVD+RW */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Write=%d, Quick start=%d, Close only=%d\n",
               !!(bp[4] & 0x1), !!(bp[5] & 0x2), !!(bp[5] & 0x1));
        break;
    case 0x2b:     /* DVD+R */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Write=%d\n", !!(bp[4] & 0x1));
        break;
    case 0x2c:     /* Rigid restricted overwrite */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      DSDG=%d, DSDR=%d, Intermediate=%d, Blank=%d\n",
               !!(bp[4] & 0x8), !!(bp[4] & 0x4), !!(bp[4] & 0x2),
               !!(bp[4] & 0x1));
        break;
    case 0x2d:     /* CD Track at once */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      BUF=%d, R-W raw=%d, R-W pack=%d, Test write=%d\n",
               !!(bp[4] & 0x40), !!(bp[4] & 0x10), !!(bp[4] & 0x8),
               !!(bp[4] & 0x4));
        printf("      CD-RW=%d, R-W sub-code=%d, Data type supported=%d\n",
               !!(bp[4] & 0x2), !!(bp[4] & 0x1),
               sg_get_unaligned_be16(bp + 6));
        break;
    case 0x2e:     /* CD mastering (session at once) */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      BUF=%d, SAO=%d, Raw MS=%d, Raw=%d\n",
               !!(bp[4] & 0x40), !!(bp[4] & 0x20), !!(bp[4] & 0x10),
               !!(bp[4] & 0x8));
        printf("      Test write=%d, CD-RW=%d, R-W=%d\n",
               !!(bp[4] & 0x4), !!(bp[4] & 0x2), !!(bp[4] & 0x1));
        printf("      Maximum cue sheet length=0x%x\n",
               sg_get_unaligned_be24(bp + 5));
        break;
    case 0x2f:     /* DVD-R/-RW write */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      BUF=%d, RDL=%d, Test write=%d, DVD-RW SL=%d\n",
               !!(bp[4] & 0x40), !!(bp[4] & 0x8), !!(bp[4] & 0x4),
               !!(bp[4] & 0x2));
        break;
    case 0x33:     /* Layer jump recording */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        num = bp[7];
        printf("      Number of link sizes=%d\n", num);
        for (k = 0; k < num; ++k)
            printf("        %d\n", bp[8 + k]);
        break;
    case 0x34:     /* Layer jump rigid restricted overwrite */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      CLJB=%d\n", !!(bp[4] & 0x1));
        printf("      Buffer block size=%d\n", bp[7]);
        break;
    /* case 0x35:     Stop long operation -> see 0x1d entry */
    case 0x37:     /* CD-RW media write support */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      CD-RW media sub-type support (bitmask)=0x%x\n", bp[5]);
        break;
    /* case 0x38:     BD-R pseudo-overwrite (POW) -> see 0x1d entry */
    case 0x3a:     /* DVD+RW dual layer */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      write=%d, quick_start=%d, close_only=%d\n",
               !!(bp[4] & 0x1), !!(bp[5] & 0x2), !!(bp[5] & 0x1));
        break;
    case 0x3b:     /* DVD+R dual layer */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      write=%d\n", !!(bp[4] & 0x1));
        break;
    case 0x40:     /* BD Read */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 32) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Bitmaps for BD-RE read support:\n");
        printf("        Class 0=0x%x, Class 1=0x%x, Class 2=0x%x, "
               "Class 3=0x%x\n", sg_get_unaligned_be16(bp + 8),
               sg_get_unaligned_be16(bp + 10),
               sg_get_unaligned_be16(bp + 12),
               sg_get_unaligned_be16(bp + 14));
        printf("      Bitmaps for BD-R read support:\n");
        printf("        Class 0=0x%x, Class 1=0x%x, Class 2=0x%x, "
               "Class 3=0x%x\n", sg_get_unaligned_be16(bp + 16),
               sg_get_unaligned_be16(bp + 18),
               sg_get_unaligned_be16(bp + 20),
               sg_get_unaligned_be16(bp + 22));
        printf("      Bitmaps for BD-ROM read support:\n");
        printf("        Class 0=0x%x, Class 1=0x%x, Class 2=0x%x, "
               "Class 3=0x%x\n", sg_get_unaligned_be16(bp + 24),
               sg_get_unaligned_be16(bp + 26),
               sg_get_unaligned_be16(bp + 28),
               sg_get_unaligned_be16(bp + 30));
        break;
    case 0x41:     /* BD Write */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 32) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      SVNR=%d\n", !!(bp[4] & 0x1));
        printf("      Bitmaps for BD-RE write support:\n");
        printf("        Class 0=0x%x, Class 1=0x%x, Class 2=0x%x, "
               "Class 3=0x%x\n", sg_get_unaligned_be16(bp + 8),
               sg_get_unaligned_be16(bp + 10),
               sg_get_unaligned_be16(bp + 12),
               sg_get_unaligned_be16(bp + 14));
        printf("      Bitmaps for BD-R write support:\n");
        printf("        Class 0=0x%x, Class 1=0x%x, Class 2=0x%x, "
               "Class 3=0x%x\n", sg_get_unaligned_be16(bp + 16),
               sg_get_unaligned_be16(bp + 18),
               sg_get_unaligned_be16(bp + 20),
               sg_get_unaligned_be16(bp + 22));
        printf("      Bitmaps for BD-ROM write support:\n");
        printf("        Class 0=0x%x, Class 1=0x%x, Class 2=0x%x, "
               "Class 3=0x%x\n", sg_get_unaligned_be16(bp + 24),
               sg_get_unaligned_be16(bp + 26),
               sg_get_unaligned_be16(bp + 28),
               sg_get_unaligned_be16(bp + 30));
        break;
    /* case 0x42:     TSR (timely safe recording) -> see 0x1d entry */
    case 0x50:     /* HD DVD Read */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      HD DVD-R=%d, HD DVD-RAM=%d\n", !!(bp[4] & 0x1),
               !!(bp[6] & 0x1));
        break;
    case 0x51:     /* HD DVD Write */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      HD DVD-R=%d, HD DVD-RAM=%d\n", !!(bp[4] & 0x1),
               !!(bp[6] & 0x1));
        break;
    case 0x52:     /* HD DVD-RW fragment recording */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      BGP=%d\n", !!(bp[4] & 0x1));
        break;
    case 0x80:     /* Hybrid disc */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      RI=%d\n", !!(bp[4] & 0x1));
        break;
    /* case 0x100:    Power management -> see 0x1d entry */
    case 0x101:    /* SMART */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      PP=%d\n", !!(bp[4] & 0x1));
        break;
    case 0x102:    /* Embedded changer */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      SCC=%d, SDP=%d, highest slot number=%d\n",
               !!(bp[4] & 0x10), !!(bp[4] & 0x4), (bp[7] & 0x1f));
        break;
    case 0x103:    /* CD audio external play (obsolete) */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Scan=%d, SCM=%d, SV=%d, number of volume levels=%d\n",
               !!(bp[4] & 0x4), !!(bp[4] & 0x2), !!(bp[4] & 0x1),
               sg_get_unaligned_be16(bp + 6));
        break;
    case 0x104:    /* Firmware upgrade */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 4) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        if (len > 4)
            printf("      M5=%d\n", !!(bp[4] & 0x1));
        break;
    case 0x105:    /* Timeout */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len > 7) {
            printf("      Group 3=%d, unit length=%d\n",
                   !!(bp[4] & 0x1), sg_get_unaligned_be16(bp + 6));
        }
        break;
    case 0x106:    /* DVD CSS */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      CSS version=%d\n", bp[7]);
        break;
    case 0x107:    /* Real time streaming */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      RBCB=%d, SCS=%d, MP2A=%d, WSPD=%d, SW=%d\n",
               !!(bp[4] & 0x10), !!(bp[4] & 0x8), !!(bp[4] & 0x4),
               !!(bp[4] & 0x2), !!(bp[4] & 0x1));
        break;
    case 0x108:    /* Drive serial number */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        num = len - 4;
        n = sizeof(buff) - 1;
        n = ((num < n) ? num : n);
        strncpy(buff, (const char *)(bp + 4), n);
        buff[n] = '\0';
        printf("      Drive serial number: %s\n", buff);
        break;
    /* case 0x109:    Media serial number -> see 0x1d entry */
    case 0x10a:    /* Disc control blocks */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        printf("      Disc control blocks:\n");
        for (k = 4; k < len; k += 4) {
            printf("        0x%x\n", sg_get_unaligned_be32(bp + k));
        }
        break;
    case 0x10b:    /* DVD CPRM */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      CPRM version=%d\n", bp[7]);
        break;
    case 0x10c:    /* firmware information */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 20) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      %.2s%.2s/%.2s/%.2s %.2s:%.2s:%.2s\n", bp + 4,
               bp + 6, bp + 8, bp + 10, bp + 12, bp + 14, bp + 16);
        break;
    case 0x10d:    /* AACS */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      BNG=%d, Block count for binding nonce=%d\n",
               !!(bp[4] & 0x1), bp[5]);
        printf("      Number of AGIDs=%d, AACS version=%d\n",
               (bp[6] & 0xf), bp[7]);
        break;
    case 0x10e:    /* DVD CSS managed recording */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Maximum number of scrambled extent information "
               "entries=%d\n", bp[4]);
        break;
    /* case 0x110:    VCPS -> see 0x1d entry */
    /* case 0x113:    SecurDisc -> see 0x1d entry */
    case 0x120:    /* BD CPS */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      BD CPS major:minor version number=%d:%d, max open "
               "SACs=%d\n", ((bp[5] >> 4) & 0xf), (bp[5] & 0xf),
               bp[6] & 0x3);
        break;
    case 0x142:    /* OSSC (Optical Security Subsystem Class) */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((bp[2] >> 2) & 0xf), !!(bp[2] & 0x2), !!(bp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("    PSAU=%d, LOSPB=%d, ME=%d\n", !!(bp[4] & 0x80),
               !!(bp[4] & 0x40), !!(bp[4] & 0x1));
        num = bp[5];
        printf("      Profile numbers:\n");
        for (k = 6; (num > 0) && (k < len); --num, k += 2) {
            printf("        %u\n", sg_get_unaligned_be16(bp + k));
        }
        break;
    default:
        pr2serr("    Unknown feature [0x%x], version=%d persist=%d, "
                "current=%d\n", feature, ((bp[2] >> 2) & 0xf),
                !!(bp[2] & 0x2), !!(bp[2] & 0x1));
        hex2stderr(bp, len, 1);
        break;
    }
}

static void
decode_config(uint8_t * resp, int max_resp_len, int len, bool brief,
              bool inner_hex)
{
    int k, curr_profile, extra_len, feature;
    uint8_t * bp;
    char buff[128];

    if (max_resp_len < len) {
        pr2serr("<<<warning: response to long for buffer, resp_len=%d>>>\n",
                len);
            len = max_resp_len;
    }
    if (len < 8) {
        pr2serr("response length too short: %d\n", len);
        return;
    }
    curr_profile = sg_get_unaligned_be16(resp + 6);
    if (0 == curr_profile)
        pr2serr("No current profile\n");
    else
        printf("Current profile: %s\n", get_profile_str(curr_profile, buff));
    printf("Features%s:\n", (brief ? " (in brief)" : ""));
    bp = resp + 8;
    len -= 8;
    for (k = 0; k < len; k += extra_len, bp += extra_len) {
        extra_len = 4 + bp[3];
        feature = sg_get_unaligned_be16(bp + 0);
        printf("  %s feature\n", get_feature_str(feature, buff));
        if (brief)
            continue;
        if (inner_hex) {
            hex2stdout(bp, extra_len, 1);
            continue;
        }
        if (0 != (extra_len % 4))
            printf("    additional length [%d] not a multiple of 4, ignore\n",
                   extra_len - 4);
        else
            decode_feature(feature, bp, extra_len);
    }
}

static void
list_known(bool brief)
{
    int k, num;

    num = SG_ARRAY_SIZE(feature_desc_arr);
    printf("Known features:\n");
    for (k = 0; k < num; ++k)
        printf("  %s [0x%x]\n", feature_desc_arr[k].desc,
               feature_desc_arr[k].val);
    if (! brief) {
        printf("Known profiles:\n");
        num = SG_ARRAY_SIZE(profile_desc_arr);
        for (k = 0; k < num; ++k)
            printf("  %s [0x%x]\n", profile_desc_arr[k].desc,
                   profile_desc_arr[k].val);
    }
}


int
main(int argc, char * argv[])
{
    bool brief = false;
    bool inner_hex = false;
    bool list = false;
    bool do_raw = false;
    bool readonly = false;
    bool verbose_given = false;
    bool version_given = false;
    int sg_fd, res, c, len;
    int peri_type = 0;
    int rt = 0;
    int starting = 0;
    int verbose = 0;
    int do_hex = 0;
    const char * device_name = NULL;
    char buff[64];
    const char * cp;
    struct sg_simple_inquiry_resp inq_resp;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "bchHilqr:Rs:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            brief = true;
            break;
        case 'c':
            rt = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++do_hex;
            break;
        case 'i':
            inner_hex = true;
            break;
        case 'l':
            list = true;
            break;
        case 'q':
            readonly = true;
            break;
        case 'r':
            rt = sg_get_num(optarg);
            if ((rt < 0) || (rt > 3)) {
                pr2serr("bad argument to '--rt'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'R':
            do_raw = true;
            break;
        case 's':
            starting = sg_get_num(optarg);
            if ((starting < 0) || (starting > 0xffff)) {
                pr2serr("bad argument to '--starting'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            verbose_given = true;
            ++verbose;
            break;
        case 'V':
            version_given = true;
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == device_name) {
            device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (verbose_given && version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        verbose_given = false;
        version_given = false;
        verbose = 0;
    } else if (! verbose_given) {
        pr2serr("set '-vv'\n");
        verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", verbose);
#else
    if (verbose_given && version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (version_given) {
        pr2serr(ME "version: %s\n", version_str);
        return 0;
    }

    if (list) {
        list_known(brief);
        return 0;
    }
    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((sg_fd = sg_cmds_open_device(device_name, true /* ro */, verbose))
        < 0) {
        pr2serr(ME "error opening file: %s (ro): %s\n", device_name,
                safe_strerror(-sg_fd));
        return sg_convert_errno(-sg_fd);
    }
    if (0 == sg_simple_inquiry(sg_fd, &inq_resp, true, verbose)) {
        if (! do_raw)
            printf("  %.8s  %.16s  %.4s\n", inq_resp.vendor, inq_resp.product,
                   inq_resp.revision);
        peri_type = inq_resp.peripheral_type;
        cp = sg_get_pdt_str(peri_type, sizeof(buff), buff);
        if (! do_raw) {
            if (strlen(cp) > 0)
                printf("  Peripheral device type: %s\n", cp);
            else
                printf("  Peripheral device type: 0x%x\n", peri_type);
        }
    } else {
        pr2serr(ME "%s doesn't respond to a SCSI INQUIRY\n", device_name);
        return SG_LIB_CAT_OTHER;
    }
    sg_cmds_close_device(sg_fd);

    sg_fd = sg_cmds_open_device(device_name, readonly, verbose);
    if (sg_fd < 0) {
        pr2serr(ME "open error (rw): %s\n", safe_strerror(-sg_fd));
        return sg_convert_errno(-sg_fd);
    }
    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    res = sg_ll_get_config(sg_fd, rt, starting, resp_buffer,
                              sizeof(resp_buffer), true, verbose);
    ret = res;
    if (0 == res) {
        len = sg_get_unaligned_be32(resp_buffer + 0) + 4;
        if (do_hex) {
            if (len > (int)sizeof(resp_buffer))
                len = sizeof(resp_buffer);
            hex2stdout(resp_buffer, len, 0);
        } else if (do_raw)
            dStrRaw((const char *)resp_buffer, len);
        else
            decode_config(resp_buffer, sizeof(resp_buffer), len, brief,
                          inner_hex);
    } else {
        char b[80];

        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Get Configuration command: %s\n", b);
        if (0 == verbose)
            pr2serr("    try '-v' option for more information\n");
    }

    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            ret = sg_convert_errno(-ret);
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_get_config failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
