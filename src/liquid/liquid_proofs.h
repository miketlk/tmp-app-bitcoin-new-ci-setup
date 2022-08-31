/**
 * Support of lightweight asset/value proofs for Liquid Network
 */

#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#define LIQUID_MAX_VALUE_PROOF_LEN 73
#define LIQUID_GENERATOR_LEN 65
#define LIQUID_COMMITMENT_LEN 33

/// Alternative generator for secp256k1
extern const uint8_t secp256k1_generator_h[LIQUID_GENERATOR_LEN];
/// Maximum allowed value for scalar
extern const uint8_t secp256k1_scalar_max[32];

/**
 * Verifies a rangeproof with a single-value range
 *
 * @param[in] proof
 *   Pointer to character array with the proof.
 * @param[in] plen
 *   Length of proof in bytes.
 * @param[in] value
 *   Value being claimed for the Pedersen commitment.
 * @param[in] commit
 *   The Pedersen commitment whose value is being proven.
 * @param[in] commit_len
 *   Length of commit in bytes.
 * @param[in] generator
 *   Additional generator 'h' encoded as: 04 x y, where x and y are encoded as big endian raw value.
 *
 * @return true if proof was valid and proved the given value, false otherwise
 */
bool liquid_rangeproof_verify_value(const uint8_t *proof,
                                    size_t plen,
                                    uint64_t value,
                                    const uint8_t *commit,
                                    size_t commit_len,
                                    const uint8_t generator[static LIQUID_GENERATOR_LEN]);

/**
 * Parses a 33-byte generator byte sequence into a generator object
 *
 * Generator is encoded as: 04 x y, where x and y are encoded as big endian raw value.
 *
 * @param[out] generator
 *    Pointer to 65-byte buffer receiving parsed generator.
 * @param[in] input
 *    Input byte sequence, 33 bytes.
 *
 * @return true if generator parsed successfully
 */
bool liquid_generator_parse(uint8_t generator[static LIQUID_GENERATOR_LEN],
                            const uint8_t input[static LIQUID_COMMITMENT_LEN]);