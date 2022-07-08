/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt data used for AIO requests processing
 * 
 * $Id$
 */

/** @page level5-ulv-aio  Corrupt data used for AIO requests processing
 *
 * @objective Check that corruption of AIO-related fields in ci_netif_state
 *            before/during processing of AIO requests does not lead to
 *            system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param sock_type     Type of the connection to be used for AIO
 * @param field         Filed to corrupt: "asyncops_ofs", "asyncops_pool",
 *                      "async_wait_id" or "async_completion_q"
 * @param when          Time of the corruption: 
 *                          "before" requests posting or
 *                          "after" requests posting.
 *
 * @par Scenario
 * -# Create a stream connection between @p pco_iut and @p pco_tst. 
 * -# If @p sock_type is @c SOCK_STREAM, overfill transmit buffers on 
 *    @p pco_iut side.
 * -# If @p when is "before", post several read and several write requests
 *    with different types of the notification (signals, callbacks, etc.).
 * -# If @p field is "asyncops_ofs", increase asyncops_ofs to point out 
 *     of shared memory.
 * -# If @p field is "asyncops_pool", set asyncops_pool to random number.
 * -# If @p field is "async_wait_id", set async_wait_id to 
 *    -# too big endpoint identifier;
 *    -# identifier corresponding to not allocated endpoint;
 *    -# identifier corresponding to free endpoint;
 *    -# identifier corresponding to existing endpoint.
 *   Choose one of above randomly.
 *    \n @htmlonly &nbsp; @endhtmlonly
 * -# If @p field is "async_completion_q" to point outside of shared memory.
 * -# If @p when is "after", post several read and several write requests
 *    with different types of the notification (signals, callbacks, etc.).
 * -# Call @b aio_suspend() for half of posted requests on @p pco_iut.
 * -# Satisfy all requests sending/receiving data from @p pco_tst.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/aio"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
