/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * User-Level Vulnerabilities testing
 * Corrupt segments of the packet iovec
 * 
 * $Id$
 */

/** @page level5-ulv-pkt_segments  Corrupt segments of the packet iovec
 *
 * @objective Check that corruption of packet structures do not lead to
 *            system crash.
 *
 * @param pco_iut       IUT PCO
 * @param pco_tst       Tester PCO
 *
 * @par Scenario
 * -# Create connection between @p pco_iut and @p pco_tst.
 * -# Corrupt freepkts: set random data to segments array and n_segmets field 
 *    of the structure ci_ip_pkt_fmt_s.
 * -# Send lot of data from @p pco_tst to provoke sending ACK.
 *
 * @author Elena Vengerova <Elena.Vengerova@oktetlabs.ru>
 */

#define TE_TEST_NAME  "ulv/pkt_segments"

int
main(int argc, char *argv[])
{
    (void)(argc); (void)(argv);
    return 0;
}
