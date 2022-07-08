/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt data used for blocking
 * 
 * $Id$
 */

/** @page level5-ulv-blocking  Corrupt data used for blocking
 *
 * @objective Check that corrupting of 
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param sock_type     Type of the connection to be used for AIO
 * @param when          Time of the corruption: 
 *                          "before" blocking or
 *                          "after" during blocking.
 * @param fake          Parameter to be passed to @ref level5-ulv-corrupt_dll
 *
 * @par Scenario
 * -# Create @p sock_type connection between @p pco_iut and @p pco_tst.
 * -# If @p when is equal to "before", apply @ref level5-ulv-corrupt_dll to
 *    post_poll_list.
 * -# Call blocking @b recv() on the connection socket on @p pco_iut.
 * -# If @p when is equal to "after", apply @ref level5-ulv-corrupt_dll to
 *    post_poll_list (from the thread of @p pco_iut).
 * -# Sleep a second.
 * -# Send data via connection from @p pco_tst.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/blocking"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
