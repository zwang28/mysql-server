/* Copyright (c) 2000, 2017, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   Without limiting anything contained in the foregoing, this file,
   which is part of C Driver for MySQL (Connector/C), is also subject to the
   Universal FOSS Exception, version 1.0, a copy of which can be found at
   http://oss.oracle.com/licenses/universal-foss-exception.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

/**
  @file mysys/checksum.cc
*/

#include <stddef.h>
#include <sys/types.h>

#include "my_inttypes.h"
#include "my_sys.h"

#if defined(__aarch64__)
#include <arm_acle.h>
#else
#include <zlib.h>
#endif
#define POINTER_IS_ALIGNED(ptr, type) ((reinterpret_cast<uintptr_t>(buf) & (sizeof (type) - 1)) == 0)
/*
  Calculate a long checksum for a memoryblock by cpu instructions.

  SYNOPSIS
    crc32_hw()
      crc       start value for crc
      pos       pointer to memory block
      length    length of the block
  RETURN
      crc32(polynomial 0x04C11DB7)
*/
#if defined(__aarch64__)
MY_ATTRIBUTE((target("arch=armv8-a+crc")))
static ha_checksum crc32_hw(ha_checksum crc, const uchar *buf, size_t len)
{
    if (buf == nullptr) return 0UL;
    crc = crc ^ 0xffffffffUL;

    /* calculate one byte crc32 result if the pointer of the buf is not aligned with half word */
    if (!POINTER_IS_ALIGNED(buf, uint16_t) && len >= 1) {
        crc = __crc32b(crc, *buf);
        len -= 1;
        buf += 1;
    }

    /* calculate half word crc32 result if the pointer of the buf is not aligned with word */
    if (!POINTER_IS_ALIGNED(buf, uint32_t) && len >= 2) {
        uint16_t *ptr = reinterpret_cast<uint16_t *>(const_cast<uchar *>(buf));
        crc = __crc32h(crc, *ptr);
        len -= 2;
        buf += 2;
    }

    /* calculate word crc32 result if the pointer of the buf is not aligned with doulbe word */
    if (!POINTER_IS_ALIGNED(buf, uint64_t) && len >= 4) {
        uint32_t *ptr = reinterpret_cast<uint32_t *>(const_cast<uchar *>(buf));
        crc = __crc32w(crc, *ptr);
        len -= 4;
        buf += 4;
    }

    /* use instruction to caclualte 8 bytes crc32 result every loop */
    while (len >= 8) {
        uint64_t *ptr = reinterpret_cast<uint64_t *>(const_cast<uchar *>(buf));
        crc = __crc32d(crc, *ptr);
        len -= 8;
        buf += 8;
    }

    /* use instruction to caclualte 4 bytes crc32 result at once */
    if (len >= 4) {
        uint32_t *ptr = reinterpret_cast<uint32_t *>(const_cast<uchar *>(buf));
        crc = __crc32w(crc, *ptr);
        len -= 4;
        buf += 4;
    }

    /* use instruction to caclualte 1 bytes crc32 result every loop*/
    if (len) {
        do {
            crc = __crc32b(crc, *buf);
            buf++;
        } while (--len);
    }
    return crc ^ 0xffffffffUL;
}
#endif

/*
  Calculate a long checksum for a memoryblock.

  SYNOPSIS
    my_checksum()
      crc       start value for crc
      pos       pointer to memory block
      length    length of the block
*/
ha_checksum my_checksum(ha_checksum crc, const uchar *pos, size_t length) {
#if defined(__aarch64__)
  return (ha_checksum)crc32_hw((uint)crc, pos, (uint)length);
#else
  return (ha_checksum)crc32((uint)crc, pos, (uint)length);
#endif
}
