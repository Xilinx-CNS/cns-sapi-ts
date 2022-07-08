/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#ifndef __OL_CMDLINE_H__
#define __OL_CMDLINE_H__

#include <stdlib.h>

/** Option type. */
typedef enum ol_cmdline_opt_type {
    OL_OPT_FLAG,    /**< Flag */
    OL_OPT_STR,     /**< String */
    OL_OPT_INT,     /**< Integer */
} ol_cmdline_opt_type;

/** User option description. */
typedef struct ol_cmdline_opt {
    const char          *name;  /**< Option name (without --). */
    ol_cmdline_opt_type  type;  /**< Type of option. */
    void                *value; /**< Pointer where the option value will be
                                     written. For @ref OL_OPT_FLAG option
                                     boolean value will be written. */
    const char          *usage; /**< String which is showed when "--help" is
                                     invoked. */
} ol_cmdline_opt;

/**
 * Process command line to find a user specified options.
 *
 * @param argc      Number of arguments in command line (from main()).
 * @param argv      Array with arguments (from main()).
 * @param opts      User defined options array.
 * @param opts_num  Number of elements in @p opts.
 *
 * @return Status code
 * @retval 0    Success
 * @retcal -1   Error
 */
int
ol_cmdline_getopt(int argc, char **argv, ol_cmdline_opt *opts,
                  size_t opts_num);

#endif /* __OL_CMDLINE_H__ */
