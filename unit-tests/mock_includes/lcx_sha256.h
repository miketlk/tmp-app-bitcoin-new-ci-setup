
/*******************************************************************************
 *   Ledger Nano S - Secure firmware
 *   (c) 2019 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#ifndef LCX_SHA256_H
#define LCX_SHA256_H

#include "sha-256.h"

/** SHA256 message digest size */
#define CX_SHA256_SIZE 32

/**
 * SHA-256 context
 */
struct cx_sha256_s {
    struct cx_hash_header_s header;
    struct Sha_256 sha_256;
    uint8_t hash[SIZE_OF_SHA_256_HASH];
};
/** Convenience type. See #cx_sha256_s. */
typedef struct cx_sha256_s cx_sha256_t;

/**
 * One shot SHA-256 digest
 *
 * @param  [in] in
 *   Input data to compute the hash
 *
 * @param  [in] len
 *   Length of input data.
 *
 * @param [out] out
 *   'out' length is implicit
 *
 */
CXCALL int cx_hash_sha256(const unsigned char WIDE *in PLENGTH(len),
                          unsigned int len,
                          unsigned char *out PLENGTH(out_len),
                          unsigned int out_len);

/**
 * @brief   Initialize a SHA-256 context.
 *
 * @param[out] hash Pointer to the context.
 *                  The context shall be in RAM.
 *
 * @return          Error code:
 *                  - CX_OK on success
 */
cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash);

#endif
