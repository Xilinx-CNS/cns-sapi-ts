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
#ifndef __SENDFILE_COMMON_H__
#define __SENDFILE_COMMON_H__

#include "sockapi-test.h"

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include "tapi_file.h"
#include "tapi_test.h"


/**
 * Buffer length used in auxiliary package utilities 
 * for sendfile() processing 
 */
#define SFTST_BUFFER    113

/** Path for file placing on Test Agent side */
#define TA_TMP_PATH     "/tmp/"

/** Path for file placing on Test Engine side */
#define TST_TMP_PATH    getenv("TE_TMP")

/**
 * Create original file to be processed on test side, copy it to the IUT side
 *
 * @param ta_        - PCO, where the original file copied.
 * @param length_    - the length of original file
 * @param pattern_   - pattern to fill in file
 * @param file_tmpl_ - original file name
 * @param file_rem_  - file name for original file copy
 */
#define PREPARE_REMOTE_FILE(ta_, length_, pattern_, file_tmpl_, file_rem_) \
    do {                                                                   \
        if (prepare_remote_file(ta_, length_, pattern_,                    \
                                file_tmpl_, file_rem_))                    \
        {                                                                  \
            TEST_STOP;                                                     \
        }                                                                  \
    } while (0)

/**
 * Create file on IUT side
 *
 * @param ta_        - PCO, where the original file created.
 * @param file_name_ - the name of created file
 * @param ptrn_      - pattern to fill in file
 * @param length_    - the length of created file
 */
#define CREATE_REMOTE_FILE(ta_, file_name_, ptrn_, length_) \
    do {                                                        \
       if (create_remote_file(ta_, file_name_, ptrn_, length_)) \
        {                                                       \
            TEST_STOP;                                          \
        }                                                       \
    } while (0)


/**
 * Remove file on IUT side
 *
 * @param ta_        - PCO, where the file removed.
 * @param file_name_ - the name of removed file
 */
#define REMOVE_REMOTE_FILE(ta_, file_name_) \
    do {                                                                \
        te_errno    err;                                                \
        char        path_name[RCF_MAX_PATH];                            \
                                                                        \
        err = rcf_ta_get_var((ta_), 0, "ta_tmp_path",                   \
                             RCF_STRING, RCF_MAX_PATH, path_name);      \
        if (err != 0)                                                   \
        {                                                               \
            ERROR("%s(): failed to get ta_tmp_path variable, rc=%r",    \
                  __FUNCTION__, err);                                   \
            strncpy(path_name, TA_TMP_PATH, RCF_MAX_PATH);              \
        }                                                               \
                                                                        \
        strncpy(path_name + strlen(path_name), (file_name_),            \
                sizeof(path_name) - strlen(path_name));                 \
                                                                        \
        if (tapi_file_ta_unlink_fmt((ta_), path_name) != 0)             \
        {                                                               \
            result = EXIT_FAILURE;                                      \
        }                                                               \
    } while (0)

/**
 * Remove file on test side
 *
 * @param file_name_ - the name of removed file
 */
#define REMOVE_LOCAL_FILE(file_name_) \
    do {                                                                \
        char *position;                                                 \
        char  path_tmpl[RCF_MAX_PATH];                                  \
                                                                        \
        strcpy(path_tmpl, TST_TMP_PATH);                                \
        position = path_tmpl + strlen(path_tmpl);                       \
        position = strncpy(position, file_name_,                        \
                           sizeof(path_tmpl) - strlen(path_tmpl));      \
                                                                        \
        if (unlink(path_tmpl))                                          \
        {                                                               \
            ERROR("removing of %s local file failure, "                 \
                  "errno=%X", path_tmpl, errno);                        \
            result = EXIT_FAILURE;                                      \
        }                                                               \
    } while (0)

/**
 * Retrieve file placed on IUT side
 *
 * @param ta_          - PCO, where the file placed
 * @param file_remote_ - the name of remote file
 * @param file_local_  - the name used to save file on test side
 */
#define RETRIEVE_REMOTE_FILE(ta_, file_remote_, file_local_) \
    do {                                                          \
        if (retrieve_remote_file(ta_, file_remote_, file_local_)) \
        {                                                         \
            TEST_STOP;                                            \
        }                                                         \
    } while (0)

/**
 * Compare files on the test side
 *
 * @param file_first_   - the name of the first file
 * @param file_second_  - the name of the second file
 */
#define COMPARE_PROCESSED_FILES(file_first_, file_second_) \
    do {                                                        \
        if (compare_processed_files(file_first_, file_second_,  \
                                     0, 0, -1))                 \
        {                                                       \
            TEST_STOP;                                          \
        }                                                       \
   } while (0)

/**
 * Compare processed file with the template on the test side
 *
 * @param tmpl_         Name of the template file
 * @param off_          Offset in the template
 * @param len_          Maximum length of the data to compare
 * @param target_       Name of the file to compare
 */
#define COMPARE_PROCESSED_WITH_TMPL(tmpl_, off_, len_, target_) \
    do {                                                            \
        if (compare_processed_files(tmpl_, target_, off_, 0, len_)) \
        {                                                           \
            TEST_STOP;                                              \
        }                                                           \
   } while (0)

/**
 * Open file on PCO by means of fopen() function, retrieve file descriptor
 * get by means of fileno()
 *
 * @param descr_       - returned descriptor succesfully opened file
 * @param pco_         - PCO, where the file placed
 * @param fname_       - the name of remote file
 * @param flags_       - flags of file opening
 * @param mode_        - mode of file when creating
 */
#define RPC_FOPEN_D(descr_, pco_, fname_, flags_, mode_) \
    do {                                                                \
        te_errno    err;                                                \
        char        path_tmpl[RCF_MAX_PATH];                            \
                                                                        \
        err = rcf_ta_get_var((pco_)->ta, 0, "ta_tmp_path",              \
                             RCF_STRING, RCF_MAX_PATH, path_tmpl);      \
        if (err != 0)                                                   \
        {                                                               \
            ERROR("%s(): failed to get ta_tmp_path variable, rc=%r",    \
                  __FUNCTION__, err);                                   \
            strncpy(path_tmpl, TA_TMP_PATH, RCF_MAX_PATH);              \
        }                                                               \
                                                                        \
        strncpy(path_tmpl + strlen(path_tmpl), (fname_),                \
                sizeof(path_tmpl) - strlen(path_tmpl));                 \
                                                                        \
        descr_ = rpc_open(pco_, path_tmpl, flags_, mode_);              \
        VERB("file %s opened with descriptor %d", fname_, descr_);      \
    } while (0)

/**
 * Retrieve file statistics
 *
 * @param fname_      The name of file to get statistics
 * @param stat_       Returned statistics
 */
#define RETRIEVE_STAT(fname_, stat_) \
   do {                                                                 \
       int   rc;                                                        \
       char *position;                                                  \
       char  path_tmpl[RCF_MAX_PATH];                                   \
                                                                        \
       strcpy(path_tmpl, TST_TMP_PATH);                                 \
       position = path_tmpl + strlen(path_tmpl);                        \
       position = strncpy(position, fname_,                             \
                           sizeof(path_tmpl) - strlen(path_tmpl));      \
                                                                        \
       rc = stat(path_tmpl, &stat_);                                    \
       if (rc == -1)                                                    \
       {                                                                \
           TEST_FAIL("stat() function failed, errno=%d", errno);        \
       }                                                                \
    } while (0)

/**
 * Create template file on the test side and copy it on the TA side.
 *
 * @param ta          TA name where 'file_tmpl' file should be passed
 * @param length      Length of the both 'file_tmpl' and 'file_new' files
 * @param pattern     Pattern for filling 'file_tmpl' file
 * @param file_tmpl   The name of template file on the test side
 *                    to be copied on the TA side
 * @param file_rem    File name on TA side
 *
 * @return @c -1 on failure, @c 0 on success
 */
extern int prepare_remote_file(const char *ta, int length, char pattern,
                               const char *file_tmpl, const char *file_rem);

/**
 * Create file on the TA side filled in with pattern.
 *
 * @param ta          TA name where 'file_name' file should be created
 * @param file_name   File name on TA side
 * @param ptrn        Pattern for filling 'file_name' file
 * @param length      Length of the 'file_name' file
 *
 * @return @c -1 on failure, @c 0 on success
 */
extern int create_remote_file(const char *ta, const char *file_name, char ptrn,
                              int length);

/**
 * Create sparse file (the file with holes) on the TA side
 * filled in with pattern.
 *
 * @param ta             TA name where 'file_name' file should be created
 * @param file_name      File name on TA side
 * @param sparse_offset  Offset to start writing payload at
 * @param payload_length Length of the payload in the created file
 * @param ptrn           Pattern for filling payload
 *
 * @return @c -1 on failure, @c 0 on success
 */
extern int create_remote_sparse_file(const char *ta, const char *file_name,
                                     int64_t sparse_offset,
                                     int64_t payload_length,
                                     char ptrn);

/**
 * Compare parts of two files on the TA side.
 *
 * @param ta             TA name where 'file_name' file should be created
 * @param file_name1     File name of the first file to compare on TA side
 * @param offset1        Offset in the first file to start comparison from
 * @param file_name2     File name of the second file to compare on TA side
 * @param offset2        Offset in the second file to start comparison from
 * @param cmp_length     Length of the date to compare
 *
 * @return @c -1 on failure, @c 0 on success
 */
extern int compare_remote_files(const char *ta,
                                const char *file_name1, int64_t offset1,
                                const char *file_name2, int64_t offset2,
                                int64_t cmp_length);

/**
 * Retrieve file placed on the TA side.
 *
 * @param ta          TA name where 'file_remote' file is placed
 * @param file_remote File name on TA side
 * @param file_local  Name for returned file on the test side
 *
 * @return @c -1 on failure, @c 0 on success
 */
extern int retrieve_remote_file(const char *ta, const char *file_remote,
                                const char *file_local);

/**
 * Compare two files on the test side
 *
 * @param file_first    File name of the first file
 * @param file_second   File name of the second file 
 * @param offset1       Offset in the first file to start
 * @param offset2       Offset in the second file to start
 * @param length        Maximum length of the data to compare
 *
 * @return @c -1 on failure, @c 0 on success
 */
extern int compare_processed_files(const char *file_first,
                                   const char *file_second,
                                   off_t offset1, off_t offset2, int length);

#endif /* !__SENDFILE_COMMON_H__ */
