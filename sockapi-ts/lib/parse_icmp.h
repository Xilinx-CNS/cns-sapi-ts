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

#ifndef __SOCKAPI_PARSE_ICMP_H__
#define __SOCKAPI_PARSE_ICMP_H__

#include "sockapi-test.h"
#include <linux/errqueue.h>

/** 
 * Structure to keep ICMP message's type and code 
 */
struct icmp_msg {
        int type; /**< Messaeg type */
        int code; /**< Message code */
};

/** 
 * Structure to keep ICMP message's type, 
 * code and expected appropriate value of 
 * the SO_ERROR socket option
 */
struct test_icmp_msg {
        unsigned int type;   /**< ICMP message type */
        unsigned int code;   /**< ICMP message code */
        rpc_errno map_errno; /**< Expected errno value regarding
                                  this ICMP message */
};

/**
 * Extract ICMP messages' type and code from the formatted
 * string.
 *
 * @param param   - formatted string to extract ICMP messages' 
 *                  type and code from it
 * @param msgs    - pointer to the array of extracted ICMP
 *                  messages' types and codes
 * @param max_num - maximun number of ICMP messages to extract
 * @param cnt     - pointer to the extracted messages' counter
 * @param err_str - pointer to the error messages' string
 *                  generated in this function
 * @return msgs, cnt and err_str (in error case)
 *
 */
int parse_icmp_msgs_param(const char *param,
                          struct icmp_msg *msgs, 
                          int max_num, int *cnt,
                          const char **err_str);

/**
 * Extract ICMP messages' type, code and expected appropriate
 * value of the SO_ERROR socket option from the formatted
 * string.
 *
 * @param param   - formatted string to extract ICMP messages' 
 *                  type and code from it
 * @param msgs    - pointer to the array of extracted ICMP
 *                  messages' types, codes and errors
 * @param max_num - maximun number of ICMP messages to extract
 * @param cnt     - pointer to the extracted messages' counter
 * @param err_str - pointer to the error messages' string
 *                  generated in this function
 * @return msgs, cnt and err_str (in error case)
 *
 */
int parse_icmp_msgs_param_with_errno(const char *param, 
                                     struct test_icmp_msg *msgs,
                                     int max_num, int *cnt,
                                     const char **err_str);

/**
 * Print struct sock_extended_err inside.
 * 
 * @param err   Pointer to the structe
 */
static inline void
sockts_print_sock_extended_err(struct sock_extended_err *err)
{
    RING("sock_extended_err: ee_errno %d, ee_origin %d, ee_type %d, "
         "ee_code %d, ee_pad %d, ee_info %d, ee_data %d", err->ee_errno,
         err->ee_origin, err->ee_type, err->ee_code,
         err->ee_pad, err->ee_info, err->ee_data);
}

/**
 * Compair error message extracted from a socket error queue with ICMP error
 * message.
 * 
 * @param msg   Sent ICMP message
 * @param err   Retrieved error
 */
extern void sockts_check_icmp_errno(struct test_icmp_msg *msg,
                                    struct sock_extended_err *err);

#endif /* __SOCKAPI_PARSE_ICMP_H__ */
