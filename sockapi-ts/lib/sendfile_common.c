/* SPDX-License-Identifier: Apache-2.0 */
/* (c) Copyright 2004 - 2022 Xilinx, Inc. All rights reserved. */
/** @file
 * @brief Socket API Test Suite
 *
 * Auxilliary functions incapsulating some common actions needed for 
 * test purposes.
 *
 * @author Igor Vasiliev <Igor.Vasiliev@oktetlabs.ru>
 *
 * $Id$
 */

#include "sendfile_common.h"

/* See the sendfile_common.h file for the description. */
int
prepare_remote_file(const char *ta, int length, char pattern,
                    const char *file_tmpl, const char *file_rem)
{
    int     rc;
    FILE   *file;
    int     len = 0;
    char    buffer[SFTST_BUFFER];
    char    path_tmpl[RCF_MAX_PATH];
    char    path_rem[RCF_MAX_PATH];

    if (ta == NULL || length < 0)
    {
        ERROR("%s(): invalide parameters", __FUNCTION__);
        return -1;
    }

    strcpy(path_tmpl, TST_TMP_PATH);

    strncpy(path_tmpl + strlen(path_tmpl), file_tmpl,
            sizeof(path_tmpl) - strlen(path_tmpl));

    file = fopen(path_tmpl, "w");
    if (file == NULL)
    {
        ERROR("%s(): template file opening failure", __FUNCTION__);
        return -1;
    }

    while (length > 0) {
        memset(buffer, pattern++, SFTST_BUFFER);
        len = (length >= SFTST_BUFFER) ? SFTST_BUFFER : length;
        fwrite(&buffer, sizeof(char), len, file);
        length -= len;
    };
    fclose(file);

    rc = rcf_ta_get_var(ta, 0, "ta_tmp_path",
                        RCF_STRING, RCF_MAX_PATH, path_rem);
    if (rc != 0)
    {
        ERROR("%s(): failed to get ta_tmp_path variable, rc=%r",
              __FUNCTION__, rc);
        strncpy(path_rem, TA_TMP_PATH, RCF_MAX_PATH);
    }

    strncpy(path_rem + strlen(path_rem), file_rem,
            sizeof(path_rem) - strlen(path_rem));

    rc = rcf_ta_put_file(ta, 0, path_tmpl, path_rem);
    if ( rc != 0)
    {
        ERROR("%s(): passing %s file failure, rc=%r",
              __FUNCTION__, path_tmpl, rc);

        if (unlink(path_tmpl))
            ERROR("removing of %s template file failure, "
                  "errno=%d", path_tmpl, errno);

        return -1;
    }
    return 0;
}

/* See the sendfile_common.h file for the description. */
int
create_remote_file(const char *ta, const char *file_name,
                   char ptrn, int length)
{
    int     rc;
    int     err;
    char    path_name[RCF_MAX_PATH] = TA_TMP_PATH;

    rc = rcf_ta_get_var(ta, 0, "ta_tmp_path",
                        RCF_STRING, RCF_MAX_PATH, path_name);
    if (rc != 0)
    {
        ERROR("%s(): failed to get ta_tmp_path variable, rc=%r",
              __FUNCTION__, rc);
        strncpy(path_name, TA_TMP_PATH, RCF_MAX_PATH);
    }

    strncpy(path_name + strlen(path_name), file_name,
            sizeof(path_name) - strlen(path_name));

    err = rcf_ta_call(ta, 0, "create_data_file", &rc, 3, FALSE,
                      RCF_STRING, path_name, RCF_INT8, ptrn,
                      RCF_INT32, length);
    if (err != 0)
    {
        ERROR("%s(): remote call failure with %r", __FUNCTION__, err);
        return -1;
    }
    if (rc != 0)
    {
        ERROR("%s(): remote routine returned rc=%r", __FUNCTION__, rc);
        return -1;
    }
    return 0;
}

/* See the sendfile_common.h file for the description. */
int
create_remote_sparse_file(const char *ta, const char *file_name,
                          int64_t sparse_offset, int64_t payload_length,
                          char ptrn)
{
    int     rc;
    int     err;
    char    path_name[RCF_MAX_PATH];

    err = rcf_ta_get_var(ta, 0, "ta_tmp_path",
                         RCF_STRING, RCF_MAX_PATH, path_name);
    if (err != 0)
    {
        ERROR("%s(): failed to get \"ta_tmp_path\" variable from %s, rc=%r",
              __FUNCTION__, ta, err);
        strncpy(path_name, TA_TMP_PATH, RCF_MAX_PATH);
    }


    strncpy(path_name + strlen(path_name), file_name,
            sizeof(path_name) - strlen(path_name));

    RING("Create remote sparse file %s on TA %s, "
         "data starts from offset=%lld, length=%lld, "
         "filled with pattern 0x%x",
         path_name, ta, sparse_offset, payload_length,
         (int)ptrn);

    err = rcf_ta_call(ta, 0, "create_sparse_file", &rc, 4, FALSE,
                      RCF_STRING, path_name, RCF_INT64, sparse_offset,
                      RCF_INT64, payload_length, RCF_INT8, ptrn);
    if (err != 0)
    {
        ERROR("%s(): remote call failure with %r", __FUNCTION__, err);
        return -1;
    }
    if (rc != 0)
    {
        ERROR("%s(): remote routine returned rc=%r", __FUNCTION__, rc);
        return -1;
    }
    return 0;
}

/* See the sendfile_common.h file for the description. */
int
compare_remote_files(const char *ta,
                     const char *file_name1, int64_t offset1,
                     const char *file_name2, int64_t offset2,
                     int64_t cmp_length)
{
    int     rc;
    int     err;
    char   *position;
    char    path_name1[RCF_MAX_PATH];
    char    path_name2[RCF_MAX_PATH];

    /* Determine the path for  */
    err = rcf_ta_get_var(ta, 0, "ta_tmp_path",
                         RCF_STRING, RCF_MAX_PATH, path_name1);
    if (err != 0)
    {
        ERROR("%s(): failed to get \"ta_tmp_path\" variable from %s, rc=%r",
              __FUNCTION__, ta, err);
        strncpy(path_name1, TA_TMP_PATH, RCF_MAX_PATH);
    }
    memcpy(path_name2, path_name1, RCF_MAX_PATH);

    position = path_name1 + strlen(path_name1);
    strncpy(position, file_name1, sizeof(path_name1) - strlen(path_name1));

    position = path_name2 + strlen(path_name2);
    strncpy(position, file_name2, sizeof(path_name2) - strlen(path_name2));

    RING("Compare remote files %s and %s on TA %s",
         path_name1, path_name2, ta);

    err = rcf_ta_call(ta, 0, "compare_files", &rc, 5, FALSE,
                      RCF_STRING, path_name1, RCF_INT64, offset1,
                      RCF_STRING, path_name2, RCF_INT64, offset2,
                      RCF_INT64, cmp_length);
    if (err != 0)
    {
        ERROR("%s(): remote call failure with %r", __FUNCTION__, err);
        return -1;
    }
    if (rc != 0)
    {
        WARN("%s(): remote routine returned rc=%r", __FUNCTION__, rc);
        return -1;
    }
    return 0;
}

/* See the sendfile_common.h file for the description. */
int
retrieve_remote_file(const char *ta, const char *file_remote, 
                     const char *file_local)
{
    int     rc;
    char    path_remote[RCF_MAX_PATH];
    char    path_local[RCF_MAX_PATH];

    rc = rcf_ta_get_var(ta, 0, "ta_tmp_path",
                        RCF_STRING, RCF_MAX_PATH, path_remote);
    if (rc != 0)
    {
        ERROR("%s(): failed to get ta_tmp_path variable, rc=%r",
              __FUNCTION__, rc);
        strncpy(path_remote, TA_TMP_PATH, RCF_MAX_PATH);
    }

    strncpy(path_remote + strlen(path_remote), file_remote,
            sizeof(path_remote) - strlen(path_remote));

    strcpy(path_local, TST_TMP_PATH);

    strncpy(path_local + strlen(path_local), file_local,
            sizeof(path_local) - strlen(path_local));

    rc = rcf_ta_get_file(ta, 0, path_remote, path_local);
    if (rc != 0)
    {
        ERROR("%s(): retrieving file failure with rc=%r", __FUNCTION__, rc);
        return -1;
    }
    return 0;
}

/* See the sendfile_common.h file for the description. */
int
compare_processed_files(const char *file_first, const char *file_second,
                        off_t offset1, off_t offset2, int length)
{
    int     rc = 0;
    char    first_buf[SFTST_BUFFER];
    char    second_buf[SFTST_BUFFER];
    int     first_eof = 0;
    int     second_eof = 0;
    char   *position;
    char    path_first[RCF_MAX_PATH];
    char    path_second[RCF_MAX_PATH];
    FILE    *first;
    FILE    *second;
    size_t  first_size = 0, second_size = 0;

    strcpy(path_first, TST_TMP_PATH);
    strcpy(path_second, TST_TMP_PATH);

    position = path_first + strlen(path_first);
    strncpy(position, file_first, sizeof(path_first) - strlen(path_first));

    position = path_second + strlen(path_second);
    strncpy(position, file_second, sizeof(path_second) - strlen(path_second));

    INFO("ENTRY to compare_processed_files(%s, %s)", path_first, path_second);

    first = fopen(path_first, "r");
    if (first == NULL)
    {
        ERROR("%s(): %s file opening failure", __FUNCTION__, path_first);
        return -1;
    }
    if (offset1 != 0)
    {
        if (fseek(first, offset1, SEEK_SET) != 0)
        {
            ERROR("%s(): fseek(first, %d, SEEK_SET) failed: %d",
                  __FUNCTION__, offset1, errno);
            return -1;
        }
    }

    second = fopen(path_second, "r");
    if (second == NULL)
    {
        ERROR("%s(): %s file opening failure", __FUNCTION__, path_second);
        fclose(first);
        return -1;
    }
    if (offset2 != 0)
    {
        if (fseek(second, offset2, SEEK_SET) != 0)
        {
            ERROR("%s(): fseek(second, %d, SEEK_SET) failed: %d",
                  __FUNCTION__, offset2, errno);
            return -1;
        }
    }

    do {
        first_size = fread(&first_buf, sizeof(char), SFTST_BUFFER, first);
        if (first_size != SFTST_BUFFER )
        {
            if (ferror(first) != 0)
            {
                ERROR("%s(): fread(%s) failed", __FUNCTION__, path_first);
                rc = -1;
                goto local_exit;
            }
            if ((first_eof = feof(first)) == 0)
            {
                ERROR("%s(): end-of-file  indicator is not set by fread(%s)",
                      __FUNCTION__, path_first);
                rc = -1;
                goto local_exit;
            }
        }
        if (length != -1 && first_size > (size_t)length)
            first_size = length;

        second_size = fread(&second_buf, sizeof(char), SFTST_BUFFER, second);
        if (second_size != SFTST_BUFFER )
        {
            if (ferror(second) != 0)
            {
                ERROR("%s(): fread(%s) failed", __FUNCTION__, path_second);
                rc = -1;
                goto local_exit;
            }
            if ((second_eof = feof(second)) == 0)
            {
                ERROR("%s(): end-of-file  indicator is not set by fread(%s)",
                      __FUNCTION__, path_second);
                rc = -1;
                goto local_exit;
            }
        }
        if (length != -1 && second_size > (size_t)length)
            second_size = length;

        if (first_size != second_size)
        {
            ERROR("%s(): Lengths of %s and %s are different", __FUNCTION__,
                  path_first, path_second);
            rc = -1;
            goto local_exit;
        }

        if (memcmp(first_buf, second_buf, first_size))
        {
            ERROR("%s(): Data into %s and %s are different", __FUNCTION__,
                  path_first, path_second);
            rc = -1;
            goto local_exit;
        }

        if (length != -1)
            length -= first_size;

    } while (!first_eof && !second_eof);

local_exit:
    fclose(first);
    fclose(second);
    return rc;
}
