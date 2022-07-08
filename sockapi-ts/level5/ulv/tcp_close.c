/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt data used during TCP socket closing
 * 
 * $Id$
 */

/** @page level5-ulv-tcp_close  Corrupt data used during TCP socket closing
 *
 * @objective Check that corruption of data used during TCP connection
 *            closing does not lead to system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 * @param fake          Parameter to be passed to @ref level5-ulv-corrupt_dll
 *
 * @par Scenario
 * -# Create TCP connection between @p pco_iut and @p pco_tst.
 * -# Apply @ref level5-ulv-corrupt_dll to timeout_q. 
 * -# Sleep 1 second.
 * -# Close TCP connection from @p pco_tst.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/tcp_close"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
