/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Macros to get Socket API test parameters.
 *
 * @author Oleg Kravtsov <Oleg.Kravtsov@oktetlabs.ru>
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __TS_SOCKAPI_PARAMS_H__
#define __TS_SOCKAPI_PARAMS_H__

#include "tapi_rpc_params.h"


/**
 * Enum for port type
 */
typedef enum {
    PORT_UNDEF, /**< zero port, for auto-binding to free user-domain port */
    PORT_SYSTEM, /**< some fixed system-domain port */
    PORT_USER,   /**< some fixed user-domain port, passed from configurator */
} sockts_port_type_t;

/**
 * The list of values allowed for parameter of type 'sockts_port_type_t'
 */
#define PORT_MAPPING_LIST \
    { "undef",  (int) PORT_UNDEF }, \
    { "system", (int) PORT_SYSTEM }, \
    { "user",   (int) PORT_USER }

/**
 * Get the value of parameter of type 'sockts_port_type_t'
 *
 * @param var_name_  Name of the variable used to get the value of
 *                   "var_name_" parameter of type 'sockts_port_type_t' (OUT)
 */
#define TEST_GET_PORT_TYPE(var_name_) \
    TEST_GET_ENUM_PARAM(var_name_, PORT_MAPPING_LIST)

/**
 * Enum for function setting NONBLOCK or CLOEXEC flags on file
 * descriptor type
 */
typedef enum {
    UNKNOWN_SET_FDFLAG = 0,
    FCNTL_SET_FDFLAG,
    SOCKET_SET_FDFLAG,
    ACCEPT4_SET_FDFLAG,
    PIPE2_SET_FDFLAG,
    IOCTL_SET_FDFLAG
} fdflag_set_func_type_t;

/**
 * The list of values allowed for parameter
 * of type 'fdflag_set_func_type_t'
 */
#define FDFLAG_SET_FUNC_MAPPING_LIST \
    {"fcntl", FCNTL_SET_FDFLAG},     \
    {"socket", SOCKET_SET_FDFLAG},   \
    {"accept4", ACCEPT4_SET_FDFLAG}, \
    {"pipe2", PIPE2_SET_FDFLAG},     \
    {"ioctl", IOCTL_SET_FDFLAG}

/**
 * Get the value of parameter of type 'fdflag_set_func_type_t'
 *
 * @param var_name_  Name of the variable used to get the value of
 *                   "var_name_" parameter of type
 *                   'fdflag_set_func_type_t' (OUT)
 */
#define TEST_GET_FDFLAG_SET_FUNC(var_name_) \
    TEST_GET_ENUM_PARAM(var_name_, FDFLAG_SET_FUNC_MAPPING_LIST)

/** Possible types of TCP connection establishment problem. */
typedef enum {
    SOCKTS_CONN_OK = 0,         /**< No problem with connection. */
    SOCKTS_CONN_REFUSED,        /**< RST is received from peer. */
    SOCKTS_CONN_TIMEOUT,        /**< Failed due to timeout. */
    SOCKTS_CONN_DELAYED,        /**< Established successfully after
                                     some delay, */
} sockts_conn_problem_t;

/**
 * Mapping list for sockts_conn_problem_t type,
 * to be passed to @b TEST_GET_ENUM_PARAM() macro to
 * parse test parameter of this type.
 */
#define SOCKTS_CONN_PROBLEM_MAPPING_LIST \
    { "ok",      SOCKTS_CONN_OK }, \
    { "refused", SOCKTS_CONN_REFUSED }, \
    { "timeout", SOCKTS_CONN_TIMEOUT }, \
    { "delayed", SOCKTS_CONN_DELAYED }

#endif /* !__TS_SOCKAPI_PARAMS_H__ */
