/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/* 
 * Socket API Test Suite
 * Advanced usage of send/receive functions
 * 
 * $Id$
 */

/** @page sendrecv-oob TCP sockets send/receive out-of-band data
 *
 * @objective Check that TCP sockets support and correctly pass 
 *            out-of-band data.
 *
 * @type conformance
 *
 * @requirement REQ-1, REQ-2, REQ-3
 *
 * @reference @ref STEVENS section 21
 *
 * @param tx        PCO to be used as out-of-band data sender
 * @param tx_s      Socket on @p tx PCO
 * @param rx        PCO to be used as out-of-band data receiver
 * @param rx_s      Socket on @p rx PCO
 * @param len       Total length of data to be sent
 * @param pos       Array with positions (0..len-1) of out-of-band data
 *                  bytes in increasing order
 *
 * @pre Sockets @p tx_s and @p rx_s are connected.
 *      Lower water mark options on transmitter and receiver are
 *      equal to 0.
 *
 * Out-of-band data are supported by TCP protocol only.  Therefore,
 * sockets should be stream with TCP protocol.
 *
 * -# Start from the first fragment of data (i=1).
 * -# Start @e out-of-band data receiver on @p rx PCO using @b recv()
 *    function with @c MSG_OOB flag.
 * -# Send @e i-th fragment of data [pos[i-1]..pos[i]] (pos[0]=0) from
 *    @p tx PCO using @b send() function with @c MSG_OOB flag.  Only
 *    the last byte is @e out-of-band data.
 * -# Check that receiver got @e out-of-band data and received byte is
 *    equal to the last sent byte.
 * -# If length of the sent fragment is greater than 1, receive normal
 *    data from @p rx_s socket using @b recv() function.
 * -# If current fragment is the last, then exit from test, otherwise
 *    increment @e i and go to the step 2.
 *
 * The test should be run with only one byte of out-of-band data without
 * any normal data when both PCOs are IUT, IUT is transmitter and RI is
 * receiver, RI is transmitter and IUT is receiver.
 *
 * @author Andrew Rybchenko <Andrew.Rybchenko@oktetlabs.ru>
 */
