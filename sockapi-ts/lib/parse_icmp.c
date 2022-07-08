/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Functions and data srtructures to extract ICMP error
 * messages' type, code and expected socket error
 * from the formatted strings.
 *  
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Konstantin Petrov <Konstantin.Petrov@oktetlabs.ru>
 * 
 * $Id$
 */

#include "te_config.h"

#if HAVE_CTYPE_H
#include <ctype.h>
#endif

#include "parse_icmp.h"

/* See description in parse_icmp.h */
int
parse_icmp_msgs_param_with_errno(const char *param, 
                                 struct test_icmp_msg *msgs,
                                 int max_num, int *cnt, 
                                 const char **err_str)
{
    static char alloc_error[] = "Not enough memory";
    static char format_error[] = "Incorrect format for icmp messages list";
    static char incorrect_errno[] = "Cannot parse errno part of "
                                    "icmp_msgs parameter";
    static char number_exceed[] = "More than allowed number of ICMP "
                                  "messages specified";
    
    char *str;
    char *buf;
    char *ptr;
    char *aux;
    int   val;

    struct param_map_entry maps[] = {
            ERRNO_MAPPING_LIST,
            { NULL, 0 },
    };

    *cnt = 0;

    if ((str = buf = strdup(param)) == NULL)
    {
        *err_str = alloc_error;
        return -1;
    }

    str--;

    do {
        /* Check number of ready messages */
        if (*cnt >= max_num)
        {
            free(buf);
            *err_str = number_exceed;
            return -1;
        }
        
        /* Set str pointer to the first nonspace character */
        do {
            str++;
        } while (isspace(*str));
        
        /* Scan ICMP type and code from the string */
        if (sscanf(str, "type:%u,code:%u,errno:",
                   &(msgs[*cnt].type), &(msgs[*cnt].code)) != 2)
        {
            free(buf);
            *err_str = format_error;
            return -1;
        }

        /* Set ptr to the beginning of the ERRNO */
        ptr = strstr(str, "errno:") + strlen("errno:");

        /* Find the end of format string and fill it with EOL */
        aux = NULL;
        if ( (aux = strchr(ptr, '/')) != NULL)
        {
            *aux = '\0';
        }
        else
        {
            char *tmp = ptr;

            /* truncate trailing spaces */
            while (!isspace(*tmp) && *tmp != '\0')
                tmp++;

            *tmp = '\0';
        }
        
        /* Convert ptr to rpc_errno */
        if (test_map_param_value("errno", maps, ptr, &val) != 0)
        {
            free(buf);
            *err_str = incorrect_errno;
            return -1;
        }
        msgs[*cnt].map_errno = (rpc_errno)val;

        /* Restore back the format symbol / */
        if (aux != NULL)
            *aux = '/';

        /* Increment counter */
        (*cnt)++;
    } while ( (str = strchr(str, '/')) != NULL);

    *err_str = NULL;
    free(buf);
    return 0;
}

/* See description in parse_icmp.h */
int
parse_icmp_msgs_param(const char *param, struct icmp_msg *msgs, int max_num,
                      int *cnt, const char **err_str)
{
    char *buf;
    char *str;

    *cnt = 0;
    if ((str = buf = (char *)malloc(strlen(param) + 1)) == NULL)
    {
        *err_str = "Not enough memory";
        return -1;
    }
    memcpy(str, param, strlen(param) + 1);
    str--;

    do {
        do {
            str++;
        } while (isspace(*str));

        if (*cnt >= max_num)
        {
            *err_str = "More than allowed number of ICMP messages "
                       "specified";
            goto err;
        }
        if (sscanf(str, "type:%d,code:%d",
                   &(msgs[*cnt].type), &(msgs[*cnt].code)) != 2)
        {
            *err_str = "Incorrect format for icmp messages list";
            goto err;
        }
        (*cnt)++;
    } while ((str = strchr(str, '/')) != NULL);

    free(buf);
    return 0;
    
err:
    free(buf);
    return -1;
}

void
sockts_check_icmp_errno(struct test_icmp_msg *msg,
                        struct sock_extended_err *err)
{
    if (errno_h2rpc(err->ee_errno) != msg->map_errno ||
        err->ee_origin != SO_EE_ORIGIN_ICMP || err->ee_type != msg->type ||
        err->ee_code != msg->code || err->ee_pad != 0)
        TEST_VERDICT("Unexpected extended socket error value was returned");
}

