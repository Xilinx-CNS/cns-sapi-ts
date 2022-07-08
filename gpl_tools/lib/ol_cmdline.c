/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/*
 * @author Sergey Nikitin <Sergey.Nikitin@oktetlabs.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>
#include "ol_cmdline.h"

/** A value returned by getopt_long() if it meets a user option. */
#define USER_OPT_RETVAL 0

static void
ol_cmdline_get_val(ol_cmdline_opt *opt, const void *opt_arg)
{
    switch (opt->type)
    {
        case OL_OPT_FLAG:
            *(bool *)opt->value = true;
            break;

        case OL_OPT_STR:
            *(char **)opt->value = strdup(opt_arg);
            break;

        case OL_OPT_INT:
            *(int *)opt->value = atoi(opt_arg);
    }
}

int
ol_cmdline_getopt(int argc, char **argv, ol_cmdline_opt *opts,
                  size_t opts_num)
{
    struct option  *options = NULL;
    int             i;
    int             rc;
    int             opt_index;
    int             retval = 0;

    /* We need to allocate 1 element more and set it to zero. */
    options = calloc(opts_num + 1, sizeof(struct option));
    assert(options != NULL);

    for (i = 0; i < opts_num; ++i)
    {
        options[i].name = opts[i].name;
        options[i].has_arg = opts[i].type == OL_OPT_FLAG ?
                             no_argument : required_argument;
        options[i].flag = NULL;
        options[i].val = USER_OPT_RETVAL;
    }

    while ((rc = getopt_long(argc, argv, "", options, &opt_index)) != -1)
    {
        if (rc == USER_OPT_RETVAL)
        {
            ol_cmdline_get_val(&opts[opt_index], optarg);
        }
        else
        {
            retval = -1;
            break;
        }
    }

    free(options);
    return retval;
}
