/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Enhanced functions for creation and releasing of vectors.
 *
 * @author Elena Vangerova <Elena.Vengerova@oktetlabs.ru>
 *
 * $Id$
 */

#ifndef __TS_RPC_IOVEC_H__
#define __TS_RPC_IOVEC_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Free the vector.
 *
 * @param vector        vector to be freed
 * @param len           length of the pattern
 */
static inline void
iovec_free(rpc_iovec *vector, int len)
{
    int i;
    
    if (vector == NULL)
        return;
        
    for (i = 0; i < len; i++)
        free(vector[i].iov_base);
        
    free(vector);
}

/**
 * Create the vector with specified lengths of elements.
 *
 * @param pattern       array with lengths of the vector elements
 * @param len           length of the pattern
 * @param vector        location for the vector
 *
 * @return length of data or -1 in the case of failure
 */
static inline int
iovec_create(int *pattern, int len, rpc_iovec **vector)
{
    int i;
    int size = 0;
    
    rpc_iovec *res;
    
    if (len == 0)
    {
        *vector = NULL;
        return 0;
    }
    
    if ((res = (rpc_iovec *)calloc(len, sizeof(rpc_iovec))) == NULL)
    {
        ERROR("No enought memory");
        return -1;
    }
    
    for (i = 0; i < len; i++)
    {
        if (pattern[i] == 0)
            continue;
            
        if ((res[i].iov_base = te_make_buf_by_len(pattern[i] + 10)) == NULL)
        {
            iovec_free(res, len);
            ERROR("No enough memory");
            return -1;
        }
        res[i].iov_len = pattern[i];
        res[i].iov_rlen = pattern[i] + 10;
        size += res[i].iov_len;
    }
    
    *vector = res;
    
    return size;
}

/**
 * Check, if data in the buffer are equal to data in the vector.
 *
 * @param vector        vector with data
 * @param len           vector length
 * @param data          data for comparison
 * @param datalen       length of data to be compared
 *
 * @return 0 if data are equal or -1 if not
 */
static inline int
iovec_check(rpc_iovec *vector, int len, char *data, int datalen)
{
    int offset = 0;
    int i;
    
    for (i = 0; i < len; i++)
    {
        int n = (datalen - offset) > (int)vector[i].iov_len ? 
                (int)vector[i].iov_len : (datalen - offset);
        
        if (n > 0 && memcmp(vector[i].iov_base, data + offset, n) != 0)
            return -1;
            
        offset += n;
    }
    
    return 0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !__TS_RPC_IOVEC_H__ */
