/*
 * memlog.h: log messages to memory
 *
 * Copyright (c) 2006-2020, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>
#include <stdbool.h>
#include <stdarg.h>
#include <compiler.h>
#include <string.h>
#include <misc.h>
#include <tboot.h>
#include <lz.h>

#include <memlog.h>


/* Memory-mapped tboot log header at the fixed log region base address. */
#define TBOOT_LOG_HDR           ((tboot_log_t *)TBOOT_SERIAL_LOG_ADDR)

/* UUID for the tboot log */
const uuid_t       tboot_log_uuid = TBOOT_LOG_UUID;

/**
 * @brief Check if the tboot log UUID is valid.
 *
 * @return 0 if the UUID is valid; otherwise -1.
 */
static int check_tboot_log_uuid(void)
{
    if ( tb_memcmp(&TBOOT_LOG_HDR->uuid, &tboot_log_uuid, sizeof(uuid_t)) != 0 )
    {
        return -1;
    }
    return 0;
}

/**
 * @brief Get the base physical address of the tboot memory log region.
 *
 * Validates that the UUID stored in the log header matches the expected
 * tboot log UUID. This way we can verify, if TBOOT LOG was initialized properly.
 *
 * @return uint32_t TBOOT_SERIAL_LOG_ADDR if the header is valid; otherwise 0.
 */
uint32_t memlog_get_base(void)
{
    if ( check_tboot_log_uuid() != 0 ) {
        return 0;
    }

    return TBOOT_SERIAL_LOG_ADDR;
}

void memlog_init(void)
{
    if ( check_tboot_log_uuid() != 0 )
    {
        uuid_t uuid = (uuid_t)TBOOT_LOG_UUID;
        tb_memcpy((void *) &TBOOT_LOG_HDR->uuid, (const void *) &uuid, sizeof(uuid_t));
        TBOOT_LOG_HDR->curr_pos = 0;
        TBOOT_LOG_HDR->zip_count = 0;
        for (uint8_t i = 0; i < ZIP_COUNT_MAX; i++)
        {
            TBOOT_LOG_HDR->zip_pos[i] = 0;
            TBOOT_LOG_HDR->zip_size[i] = 0;
        }
    }

    /* initialize these post-launch as well, since bad/malicious values */
    /* could compromise environment */
    TBOOT_LOG_HDR->max_size = TBOOT_SERIAL_LOG_SIZE - sizeof(tboot_log_t);

    /* if we're calling this post-launch, verify that curr_pos is valid */
    if ( TBOOT_LOG_HDR->zip_pos[TBOOT_LOG_HDR->zip_count] > TBOOT_LOG_HDR->max_size)
    {
        TBOOT_LOG_HDR->curr_pos = 0;

        /* Match TBOOT LOG UUID as corrupted, when TBOOT LOG exceeds */
        /* it's maximal size */
        tb_memset(((void *) &TBOOT_LOG_HDR->uuid), 0, sizeof(uuid_t));
        for ( uint8_t i = 0; i < ZIP_COUNT_MAX; i++ )
        {
            TBOOT_LOG_HDR->zip_pos[i] = 0;
            TBOOT_LOG_HDR->zip_size[i] = 0;
        }
    }

    if ( TBOOT_LOG_HDR->curr_pos > TBOOT_LOG_HDR->max_size )
    {
        TBOOT_LOG_HDR->curr_pos = TBOOT_LOG_HDR->zip_pos[TBOOT_LOG_HDR->zip_count];
    }
}

void memlog_write(const char *str, unsigned int count)
{
    if ( check_tboot_log_uuid() != 0 || count > TBOOT_LOG_HDR->max_size ) {
        return;
    }

    /* Check if there is space for the new string and a null terminator  */
    if (TBOOT_LOG_HDR->curr_pos + count + 1> TBOOT_LOG_HDR->max_size) {
        memlog_compress(count);
    }

    tb_memcpy(&TBOOT_LOG_HDR->buf[TBOOT_LOG_HDR->curr_pos], str, count);
    TBOOT_LOG_HDR->curr_pos += count;

    /* if the string wasn't NULL-terminated, then NULL-terminate the log */
    if ( str[count-1] != '\0' )
        TBOOT_LOG_HDR->buf[TBOOT_LOG_HDR->curr_pos] = '\0';
    else {
        /* so that curr_pos will point to the NULL and be overwritten */
        /* on next copy */
        TBOOT_LOG_HDR->curr_pos--;
    }
}

void memlog_compress(uint32_t required_space)
{
    /* allocate a 64K temp buffer for compressed log  */
    static char buf[64*1024];
    char *out=buf;
    int zip_size;
    uint32_t zip_pos;
    bool log_reset_flag;

    if (required_space == 0 && TBOOT_LOG_HDR->curr_pos < TBOOT_LOG_HDR->max_size / 2) {
        /* Flush was requested, but we have over half buffer free, skip it */
        return;
    }

    /* If there are space issues, only then log will be reset */
    log_reset_flag = false;

    /* Check if there is space to add another compressed chunk */
    if(TBOOT_LOG_HDR->zip_count >= ZIP_COUNT_MAX)
        log_reset_flag = true;
    else{
        /* Get the start position of the new compressed chunk */
        zip_pos = TBOOT_LOG_HDR->zip_pos[TBOOT_LOG_HDR->zip_count];

        /*  Compress the last part of the log buffer that is not compressed,
            and put the compressed output in out (buf) */
        zip_size = LZ_Compress(&TBOOT_LOG_HDR->buf[zip_pos], out, (TBOOT_LOG_HDR->curr_pos - zip_pos), sizeof(buf) );

        /* Check if buf was large enough for LZ_compress to succeed */
        if( zip_size < 0 )
            log_reset_flag = true;
        else{
            /*  Check if there is space to add the compressed string, the
                new string and a null terminator to the log */
            if( (zip_pos + zip_size + required_space + 1) > TBOOT_LOG_HDR->max_size )
                log_reset_flag = true;
            else{
                /*  Add the new compressed chunk to the log buffer,
                    over-writing the last part of the log that was just
                    compressed */
                tb_memcpy(&TBOOT_LOG_HDR->buf[zip_pos], out, zip_size);
                TBOOT_LOG_HDR->zip_size[TBOOT_LOG_HDR->zip_count] = zip_size;
                TBOOT_LOG_HDR->zip_count++;
                TBOOT_LOG_HDR->curr_pos = zip_pos + zip_size;

                /*  Set a NULL ending */
                TBOOT_LOG_HDR->buf[TBOOT_LOG_HDR->curr_pos] ='\0';

                /*  Only if there is space to add another compressed chunk,
                    prepare its start position. */
                if( TBOOT_LOG_HDR->zip_count < ZIP_COUNT_MAX )
                    TBOOT_LOG_HDR->zip_pos[TBOOT_LOG_HDR->zip_count] = TBOOT_LOG_HDR->curr_pos;
            }
        }
    }

    /* There was some space-shortage problem. Reset the log. */
    if ( log_reset_flag )
    {
        TBOOT_LOG_HDR->curr_pos = 0;
        for (uint8_t i = 0; i < ZIP_COUNT_MAX; i++ )
        {
            TBOOT_LOG_HDR->zip_pos[i]  = 0;
            TBOOT_LOG_HDR->zip_size[i] = 0;
        }

        TBOOT_LOG_HDR->zip_count = 0;
    }
}