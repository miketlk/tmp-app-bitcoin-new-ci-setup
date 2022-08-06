/**
 * Support of lightweight asset/value proofs for Liquid Network
 */

#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

/// Alternative generator for secp256k1
extern const uint8_t secp256k1_generator_h[65];
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
                                    const uint8_t generator[static 65]);