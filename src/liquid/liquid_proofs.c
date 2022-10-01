/**********************************************************************
 * Support of lightweight asset/value proofs is ported from           *
 * libsecp256k1-zkp. Original copyright is following:                 *
 *                                                                    *
 * Copyright (c) 2014-2015 Gregory Maxwell                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifdef HAVE_LIQUID

#include <stdint.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "cx_stubs.h"
#include "lcx_math.h"
#include "cx_errors.h"
#include "ox_ec.h"

#include "write.h"
#include "crypto.h"
#include "liquid.h"
#include "liquid_proofs.h"
#include "tests.h"

/// Unpacks a constant into an array of 32 bytes
#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) { .n = { \
    (d7) >> 24 & 0xff, (d7) >> 16 & 0xff, (d7) >> 8 & 0xff, (d7) & 0xff, \
    (d6) >> 24 & 0xff, (d6) >> 16 & 0xff, (d6) >> 8 & 0xff, (d6) & 0xff, \
    (d5) >> 24 & 0xff, (d5) >> 16 & 0xff, (d5) >> 8 & 0xff, (d5) & 0xff, \
    (d4) >> 24 & 0xff, (d4) >> 16 & 0xff, (d4) >> 8 & 0xff, (d4) & 0xff, \
    (d3) >> 24 & 0xff, (d3) >> 16 & 0xff, (d3) >> 8 & 0xff, (d3) & 0xff, \
    (d2) >> 24 & 0xff, (d2) >> 16 & 0xff, (d2) >> 8 & 0xff, (d2) & 0xff, \
    (d1) >> 24 & 0xff, (d1) >> 16 & 0xff, (d1) >> 8 & 0xff, (d1) & 0xff, \
    (d0) >> 24 & 0xff, (d0) >> 16 & 0xff, (d0) >> 8 & 0xff, (d0) & 0xff } }

/// Offsets withing 65-byte curve point
typedef enum {
    GE_OFFSET_PREFIX = 0,   ///< Prefix: 0x04
    GE_OFFSET_X = 1,        ///< X-coordinate
    GE_OFFSET_Y = (1 + 32)  ///< Y-coordinate
} ge_offset_t;

/// A scalar modulo the group order of the secp256k1 curve. */
typedef struct {
    uint8_t n[32];
} secp256k1_scalar;

/// A field element
typedef secp256k1_scalar secp256k1_fe;

/**
 * A group element in affine coordinates on the secp256k1 curve, or occasionally on an isomorphic
 * curve of the form y^2 = x^3 + 7*t^6
 */
typedef struct {
    /// Curve point encoded as 04 x y, where x and y are encoded as big endian raw value
    uint8_t n[65];
} secp256k1_ge;

/** Alternative generator for secp256k1.
 *  This is the sha256 of 'g' after standard encoding (without compression),
 *  which happens to be a point on the curve. More precisely, the generator is
 *  derived by running the following script with the sage mathematics software.

    import hashlib
    F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    G = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
    H = EllipticCurve ([F (0), F (7)]).lift_x(F(int(hashlib.sha256(G.decode('hex')).hexdigest(),16)))
    print('%x %x' % H.xy())
 */
const uint8_t secp256k1_generator_h[LIQUID_GENERATOR_LEN] = {
    0x04,
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e, 0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
    0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68, 0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
};

/// Maximum allowed value for scalar
const uint8_t secp256k1_scalar_max[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40
};

/**
 * Checks scalar value for overflow
 *
 * @param[in] a
 *   Scalar value to check.
 *
 * @return true if overflow is detected
 */
static inline bool secp256k1_scalar_check_overflow(const uint8_t a[static 32]) {
    return cx_math_cmp(a, secp256k1_scalar_max, 32) > 0;
}

/**
 * Check whether a scalar equals zero
 *
 * @param[in] a
 *   Scalar to check
 *
 * @return true if scalar is zero
 */
#if 0
static inline bool secp256k1_scalar_is_zero(const secp256k1_scalar *a) {
    return !!cx_math_is_zero(a->n, sizeof(a->n));
}
#endif

/**
 * Sets a group element (affine) equal to the point with the given X coordinate and a Y coordinate
 * that is a quadratic residue modulo p.
 *
 * @param[out] r
 *   Resulting group element encoded as 04 x y.
 * @param[in] x
 *   X coordinate of a point.
 */
static void secp256k1_ge_set_xquad(uint8_t r[static 65], const uint8_t x[static 32]) {
    uint8_t *res_x = &r[1], *res_y = &r[1 + 32];
    uint8_t *scalar = res_x;

    // We use res_x and res_y for intermediate results, in order to save memory

    // tmp = x^3 (mod p)
    uint8_t e = 3;
    cx_math_powm(res_y, x, &e, 1, secp256k1_p, 32);

    // tmp = x^3 + 7 (mod p)
    memset(scalar, 0, 31);
    scalar[31] = 7;
    cx_math_addm(res_y, res_y, scalar, secp256k1_p, 32);

    // y = sqrt(x^3 + 7) (mod p)
    cx_math_powm(res_y, res_y, secp256k1_sqr_exponent, 32, secp256k1_p, 32);

    memmove(res_x, x, 32);  // copy x
    r[0] = 0x04;
}

/**
 * Set r equal to the inverse of a (i.e., mirrored around the X axis)
 *
 * @param[out] r
 *   Resulting point encoded as 04 x y.
 * @param[in] a
 *   Point to compute inverse encoded as 04 x y.
 */
static inline void secp256k1_ge_neg(uint8_t r[static 65], const uint8_t a[static 65]) {
    uint8_t *res_y = &r[1 + 32];
    const uint8_t *arg_y = &a[1 + 32];
    if (r != a) {
        memcpy(r, a, 1 + 32); // copy 0x04 byte and x coordinate
    }
    cx_math_sub(res_y, secp256k1_p, arg_y, 32);
}

// TODO: remove
/**
 * Set r equal to the sum of a and b
 *
 * @param[out] r
 *    Resulting point encoded as 04 x y.
 * @param[in] a
 *    First operand: point on curve encoded as 04 x y.
 * @param[in] b
 *    Second operand: point on curve encoded as 04 x y.
 */
static inline void secp256k1_add(uint8_t r[static 65],
                                 const uint8_t a[static 65],
                                 const uint8_t b[static 65]) {
    if(0 == cx_ecfp_add_point(CX_CURVE_SECP256K1, r, a, b, 32)) {
        THROW(CX_EC_INFINITE_POINT);
    }
}

/**
 * Set r equal to the sum of a and b
 *
 * @param[out] r
 *    Resulting group element.
 * @param[in] a
 *    First operand.
 * @param[in] b
 *    Second operand.
 */
static inline void secp256k1_ge_add(secp256k1_ge *r,
                                    secp256k1_ge *a,
                                    secp256k1_ge *b) {
    if(0 == cx_ecfp_add_point(CX_CURVE_SECP256K1, r->n, a->n, b->n, 32)) {
        THROW(CX_EC_INFINITE_POINT);
    }
}

/**
 * Performs a scalar multiplication over an elliptic curve.
 *
 * @param[in, out] point
 *    Point on curve encoded as 04 x y. Also used for the result.
 * @param[in] scalar
 *    Scalar encoded as big endian integer.
 */
static inline void secp256k1_scalar_mult(uint8_t point[static 65],
                                         const uint8_t scalar[static 32]) {
    if(0 == cx_ecfp_scalar_mult(CX_CURVE_SECP256K1, point, 65, scalar, 32)) {
        THROW(CX_EC_INFINITE_POINT);
    }
}

/**
 * Loads serialized Pedersen commitment
 *
 * @param[out] ge
 *   Resulting group element encoded as 04 x y.
 * @param[in] commit
 *   Serialized commitment, 33 bytes.
 */
static void pedersen_commitment_load(uint8_t ge[static 65],
                                     const uint8_t commit[static 33]) {
    secp256k1_ge_set_xquad(ge, &commit[1]);
    if (commit[0] & 1) {
        secp256k1_ge_neg(ge, ge);
    }
}

/**
 * Multiplies a small number with the generator: r = gn*G2
 *
 * @param[out] r
 *   Resulting point encoded as 04 x y.
 * @param gn
 *   Number to multiply.
 * @param genp
 *   Generator point encoded as 04 x y.
 */
static void pedersen_ecmult_small(uint8_t r[static 65], uint64_t gn,
                                  const uint8_t genp[static 65]) {
    uint8_t scalar[32];
    enum { GN_OFFSET = sizeof(scalar) - 8 };

    memset(scalar, 0, GN_OFFSET);
    write_u64_be(scalar, GN_OFFSET, gn);
    memcpy(r, genp, 65);
    bool ok = 0 != cx_ecfp_scalar_mult(CX_CURVE_SECP256K1, r, 65, scalar, sizeof(scalar));
    explicit_bzero(&scalar, sizeof(scalar));

    if(!ok) {
        THROW(CX_EC_INFINITE_POINT);
    }
}

/**
 * Checks whether a field element is a quadratic residue.
 *
 * @param[in] a
 *   Value to check.
 *
 * @return true a field element is a quadratic residue.
 */
static bool secp256k1_fe_is_quad_var(const uint8_t a[static 32]) {
	static const uint8_t p_one_shr[32] = {
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xfe, 0x17
    };
	uint8_t res[32];

    if (cx_math_is_zero(a, 32)) {
        return true;
    }
	cx_math_powm(res, a, p_one_shr, 32, secp256k1_p, 32);
	if (!cx_math_is_zero(res, 30)) {
		return false;
	}
	return res[31] == 1;
}

/**
 * Sets a field element to be the product of two others
 *
 * @param[out] r
 *    Resulting field element.
 * @param[in] a
 *    First field element to multiply.
 * @param[in] b
 *    Second field element to multiply.
 */
static inline void secp256k1_fe_mul(secp256k1_fe *r,
                                    const secp256k1_fe *a,
                                    const secp256k1_fe *b) {
    cx_math_multm(r->n, a->n, b->n, secp256k1_p, 32);
}

/**
 * Sets a field element to be the square of another
 *
 * @param[out] r
 *    Resulting field element.
 * @param[in] a
 *    Argument field element.
 */
static inline void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a) {
    uint8_t e = 2;
    cx_math_powm(r->n, a->n, &e, 1, secp256k1_p, 32);
}

/**
 * Adds a field element to another
 *
 * @param[in, out] r
 *    First argument, also receives results.
 * @param[in] a
 *    Second argument.
 */
static inline void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a) {
    cx_math_addm(r->n, r->n, a->n, secp256k1_p, 32);
}

/**
 * Sets a field element equal to the additive inverse of another
 *
 * @param[out] r
 *    Resulting field element.
 * @param[in] a
 *    Argument field element.
 */
static inline void secp256k1_fe_negate(secp256k1_fe *r, const secp256k1_fe *a) {
    cx_math_sub(r->n, secp256k1_p, a->n, 32);
}

/**
 * Sets a field element to be the (modular) inverse of another.
 *
 * @param[out] r
 *    Resulting field element.
 * @param[in] a
 *    Argument field element.
 */
static void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *a) {
    cx_math_invprimem(r->n, a->n, secp256k1_p, 32);
}

/**
 * Computes a square root of a given field element
 *
 * @param[out] r
 *    Resulting field element.
 * @param[in] a
 *    Argument field element.
 *
 * @return 1 if square root is successfully computed, otherwise 0
 */
static int secp256k1_fe_sqrt(secp256k1_fe *r, const secp256k1_fe *a) {
    cx_math_powm(r->n, a->n, secp256k1_sqr_exponent, 32, secp256k1_p, 32);  // y = sqrt(a) (mod p)

    secp256k1_fe y_2;
    secp256k1_fe_sqr(&y_2, r);
    return 0 == cx_math_cmp(y_2.n, a->n, 32);
}

/**
 * If flag is true, sets *r equal to *a; otherwise leaves it as is
 *
 * @param[out] r
 *    Resulting field element.
 * @param[in] a
 *    Argument field element.
 * @param[in] flag
 *    Flag controlling assignment.
 */
static void secp256k1_fe_cmov(secp256k1_fe *r, const secp256k1_fe *a, int flag) {
    uint8_t *p_r = r->n;
    const uint8_t *p_a = a->n;
    uint8_t mask0 = flag + ~((uint8_t)0);
    uint8_t mask1 = ~mask0;

    for(int i = 0; i < 32; ++i, p_r++) {
        *p_r = (*p_r & mask0) | (*(p_a++) & mask1);
    }
}

/**
 * Initializes group elements with given x and y coordinates
 *
 * @param[out] r
 *   Resulting group element.
 * @param[in] x
 *   Field element representing x coordinate
 * @param y
 *   Field element representing y coordinate
 */
static inline void secp256k1_ge_set_xy(secp256k1_ge *r, const secp256k1_fe *x, const secp256k1_fe *y) {
    r->n[GE_OFFSET_PREFIX] = 0x04;
    memcpy(r->n + GE_OFFSET_X, x->n, 32);
    memcpy(r->n + GE_OFFSET_Y, y->n, 32);
}

/**
 * Checks the "oddness" of a field element
 *
 * @param[in] a
 *   Field element to check.
 *
 * @return 1 if field element is odd, 0 otherwise
 */
static inline int secp256k1_fe_is_odd(const secp256k1_fe *a) {
    return a->n[31] & 1;
}

/**
 * Convenience wrapper for crypto_hash_update, updating a hash with a point on elliptic curve.
 *
 * @param[in] hash_context
 *   The context of the hash, which must already be initialized.
 * @param[in] point
 *   Point encoded as 04 x y.
 */
static void hash_update_point(cx_hash_t *hash_context, const uint8_t point[static 65]) {
    const uint8_t *point_x = &point[1], *point_y = &point[1 + 32];
    crypto_hash_update_u8(hash_context, !secp256k1_fe_is_quad_var(point_y));
    crypto_hash_update(hash_context, point_x, 32);
}

/**
 * Computes hash for Borromean ring signature scheme
 *
 * @param[out] hash
 *   Resulting 256 bit hash.
 * @param[in] m
 *   Message.
 * @param[in] mlen
 *   Length of message in bytes.
 * @param[in] e
 *   Parameter e.
 * @param[in] elen
 *   Length of e in bytes.
 * @param[in] ridx
 *   Ring index.
 * @param[in] eidx
 *   Index of e.
 */
static void borromean_hash(uint8_t hash[static 32],
                           const uint8_t *m,
                           size_t mlen,
                           const uint8_t *e,
                           size_t elen,
                           size_t ridx,
                           size_t eidx) {
    cx_sha256_t sha256_en;
    cx_sha256_init(&sha256_en);
    crypto_hash_update(&sha256_en.header, e, elen);
    crypto_hash_update(&sha256_en.header, m, mlen);
    crypto_hash_update_u32(&sha256_en.header, ridx);
    crypto_hash_update_u32(&sha256_en.header, eidx);
    crypto_hash_digest(&sha256_en.header, hash, 32);
}

bool liquid_rangeproof_verify_exact(const uint8_t *proof,
                                    size_t plen,
                                    uint64_t value,
                                    const uint8_t *commit,
                                    size_t commit_len,
                                    const uint8_t generator[static LIQUID_GENERATOR_LEN]) {
    if(!proof || !(plen == 73 || plen == 65) || !commit || commit_len != 33 || !generator ||
       generator[0] != 0x04) {
        return false;
    }

    size_t offset;

    /* 0x80 must be unset for any rangeproof; 0x40 indicates "has nonzero range"
    * so must also be unset for single-value proofs */
    if ((proof[0] & 0xC0) != 0x00) {
        return 0;
    }

    /* Verify that value in the header is what we expect; 0x20 is "has nonzero min-value" */
    if ((proof[0] & 0x20) == 0x00) {
        if (value != 0) {
            return false;
        }
        offset = 1;
    } else {
        int i;
        uint64_t claimed = 0;
        for (i = 0; i < 8; i++) {
            claimed = (claimed << 8) | proof[1 + i];
        }
        if (value != claimed) {
            return false;
        }
        offset = 9;
    }

    uint8_t commitp[65];
    uint8_t tmp[65];
    uint8_t tmpch[33];
    uint8_t pp_comm[32];
    uint8_t es[32];
    uint8_t ss[32];

    bool result = false;
    BEGIN_TRY {
        TRY {
            // Subtract value from commitment; store modified commitment in tmp
            pedersen_commitment_load(commitp, commit);
            // Let's check if value is 0 and multiplication will result in point at infinity
            if(value) {
                pedersen_ecmult_small(tmp, value, generator);
                secp256k1_ge_neg(tmp, tmp);
                secp256k1_add(tmp, tmp, commitp);
            } else {
                // Value is 0 thus we just keep commitment point "as is" because infinity point is
                // an identity element
                memcpy(tmp, commitp, sizeof(tmp));
            }

            // Now we just have a Schnorr signature in (e, s) form. The verification equation is:
            // e == H(sG - eX || proof params)

            // 1. Compute slow/overwrought commitment to proof params
            {
                cx_sha256_t sha2;
                cx_sha256_init(&sha2);
                hash_update_point(&sha2.header, commitp);
                hash_update_point(&sha2.header, generator);
                crypto_hash_update(&sha2.header, proof, offset);
                crypto_hash_digest(&sha2.header, pp_comm, sizeof(pp_comm));
            }

            // ... feed this into our hash
            borromean_hash(es, pp_comm, 32, &proof[offset], 32, 0, 0);
            if(secp256k1_scalar_check_overflow(es) || cx_math_is_zero(es, sizeof(es))) {
                THROW(CX_OVERFLOW);
            }

            // 1. Compute R = sG - eX
            memcpy(ss, &proof[offset + 32], sizeof(ss));
            if(secp256k1_scalar_check_overflow(ss) || cx_math_is_zero(ss, sizeof(ss))) {
                THROW(CX_OVERFLOW);
            }

            // Double multiply: tmp = es*tmp + ss*G
            {
                uint8_t tmp2[65];
                secp256k1_scalar_mult(tmp, es);
                memcpy(tmp2, secp256k1_generator, sizeof(tmp2));
                secp256k1_scalar_mult(tmp2, ss);
                secp256k1_add(tmp, tmp, tmp2);
                crypto_get_compressed_pubkey(tmp, tmpch);
            }

            // 2. Compute e = H(R || proof params)
            {
                cx_sha256_t sha2;
                cx_sha256_init(&sha2);
                crypto_hash_update(&sha2.header, tmpch, 33);
                crypto_hash_update(&sha2.header, pp_comm, sizeof(pp_comm));
                crypto_hash_digest(&sha2.header, tmpch, sizeof(tmpch));
            }

            // 3. Check computed e against original e
            result = (0 == memcmp(tmpch, &proof[offset], 32));
        }
        CATCH_ALL {
            result = false;
        }
        FINALLY {
            // Zeroize sensitive data here
        }
    }
    END_TRY;
    return result;
}

bool liquid_generator_parse(uint8_t generator[static LIQUID_GENERATOR_LEN],
                            const uint8_t input[static LIQUID_COMMITMENT_LEN]) {
    if (!generator || !input || (input[0] & 0xFE) != 10) {
        return false;
    }

    bool result = false;
    BEGIN_TRY {
        TRY {
            secp256k1_ge_set_xquad(generator, &input[1]);
            if (input[0] & 1) {
                secp256k1_ge_neg(generator, generator);
            }
            result = true;
        }
        CATCH_ALL {
            result = false;
        }
        FINALLY {
            // Zeroize sensitive data here
        }
    }
    END_TRY;
    return result;
}

/**
 * Computes a hash message from a single input asset tag and an output tag
 *
 * @param[out] msg32
 *    Resulting message.
 * @param input_tag
 *    The ephemeral asset tag of the sole input, a point encoded as 04 x y.
 * @param output_tag
 *    The ephemeral asset tag of the output, a point encoded as 04 x y.
 */
static void secp256k1_surjection_genmessage_single(
    uint8_t msg32[static 32],
    const uint8_t input_tag[static LIQUID_GENERATOR_LEN],
    const uint8_t output_tag[static LIQUID_GENERATOR_LEN]) {

    cx_sha256_t sha256_en;
    cx_sha256_init(&sha256_en);

    crypto_hash_update_u8(&sha256_en.header, 2 + (input_tag[64] & 1)); // LSB of y coordinate
    crypto_hash_update(&sha256_en.header, &input_tag[1], 32); // x coordinate

    crypto_hash_update_u8(&sha256_en.header, 2 + (output_tag[64] & 1)); // LSB of y coordinate
    crypto_hash_update(&sha256_en.header, &output_tag[1], 32); // x coordinate

    crypto_hash_digest(&sha256_en.header, msg32, 32);
}

bool liquid_surjectionproof_verify_single(const uint8_t *proof,
                                          size_t plen,
                                          const uint8_t input_tag[static LIQUID_GENERATOR_LEN],
                                          const uint8_t output_tag[static LIQUID_GENERATOR_LEN]) {

    if(!proof || plen != 67 ||
       proof[0] != 0x01 || proof[1] != 0x00 || // n_inputs, LE 16-bit integer
       proof[2] != 0x01 ||                     // used_inputs, bitmap, 1 byte for single input
       !input_tag || !output_tag || input_tag[0] != 0x04 || output_tag[0] != 0x04) {
        return false;
    }

    const uint8_t *proof_data = proof + 3;
    uint8_t tmp[65];
    uint8_t es[32];
    uint8_t ss[32];
    uint8_t tmpch[33];
    uint8_t pp_comm[32];

    bool result = false;
    BEGIN_TRY {
        TRY {
            secp256k1_ge_neg(tmp, input_tag);
            secp256k1_add(tmp, tmp, output_tag);

            /* Now we just have a Schnorr signature in (e, s) form. The verification
            * equation is e == H(sG - eX || proof params), where X is the difference
            * between the output and input. */

            // 1. Compute slow/overwrought commitment to proof params
            secp256k1_surjection_genmessage_single(pp_comm, input_tag, output_tag);
            // (past this point the code is identical to rangeproof_verify_value)

            // ... feed this into our hash
            borromean_hash(es, pp_comm, 32, &proof_data[0], 32, 0, 0);
            if(secp256k1_scalar_check_overflow(es) || cx_math_is_zero(es, sizeof(es))) {
                THROW(CX_OVERFLOW);
            }

            // 1. Compute R = sG - eX
            memcpy(ss, &proof_data[32], sizeof(ss));
            if(secp256k1_scalar_check_overflow(ss) || cx_math_is_zero(ss, sizeof(ss))) {
                THROW(CX_OVERFLOW);
            }

            // Double multiply: tmp = es*tmp + ss*G
            {
                uint8_t tmp2[65];
                secp256k1_scalar_mult(tmp, es);
                memcpy(tmp2, secp256k1_generator, sizeof(tmp2));
                secp256k1_scalar_mult(tmp2, ss);
                secp256k1_add(tmp, tmp, tmp2);
                crypto_get_compressed_pubkey(tmp, tmpch);
            }

            // 2. Compute e = H(R || proof params)
            {
                cx_sha256_t sha2;
                cx_sha256_init(&sha2);
                crypto_hash_update(&sha2.header, tmpch, 33);
                crypto_hash_update(&sha2.header, pp_comm, sizeof(pp_comm));
                crypto_hash_digest(&sha2.header, tmpch, sizeof(tmpch));
            }

            // 3. Check computed e against original e
            result = (0 == memcmp(tmpch, &proof_data[0], 32));
        }
        CATCH_ALL {
            result = false;
        }
        FINALLY {
            // Zeroize sensitive data here
        }
    }
    END_TRY;
    return result;
}

// TODO: document
static void shallue_van_de_woestijne(secp256k1_ge* ge, const secp256k1_fe* t) {
    /* Implements the algorithm from:
     *    Indifferentiable Hashing to Barreto-Naehrig Curves
     *    Pierre-Alain Fouque and Mehdi Tibouchi
     *    Latincrypt 2012
     */

    /* Basic algorithm:

       c = sqrt(-3)
       d = (c - 1)/2

       w = c * t / (1 + b + t^2)  [with b = 7]
       x1 = d - t*w
       x2 = -(x1 + 1)
       x3 = 1 + 1/w^2

       To avoid the 2 divisions, compute the above in numerator/denominator form:
       wn = c * t
       wd = 1 + 7 + t^2
       x1n = d*wd - t*wn
       x1d = wd
       x2n = -(x1n + wd)
       x2d = wd
       x3n = wd^2 + c^2 + t^2
       x3d = (c * t)^2

       The joint denominator j = wd * c^2 * t^2, and
       1 / x1d = 1/j * c^2 * t^2
       1 / x2d = x3d = 1/j * wd
    */

    static const secp256k1_fe c = SECP256K1_FE_CONST(0x0a2d2ba9, 0x3507f1df, 0x233770c2, 0xa797962c, 0xc61f6d15, 0xda14ecd4, 0x7d8d27ae, 0x1cd5f852);
    static const secp256k1_fe d = SECP256K1_FE_CONST(0x851695d4, 0x9a83f8ef, 0x919bb861, 0x53cbcb16, 0x630fb68a, 0xed0a766a, 0x3ec693d6, 0x8e6afa40);
    static const secp256k1_fe b = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 7);
    static const secp256k1_fe b_plus_one = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 8);

    secp256k1_fe tmp, x1, x2, x3;
    int alphaquad, betaquad;

    {
        secp256k1_fe wn, wd, x1n, x2n, x3n, x3d, jinv;
        secp256k1_fe_mul(&wn, &c, t); /* mag 1 */
        secp256k1_fe_sqr(&wd, t); /* mag 1 */
        secp256k1_fe_add(&wd, &b_plus_one); /* mag 2 */
        secp256k1_fe_mul(&tmp, t, &wn); /* mag 1 */
        secp256k1_fe_negate(&tmp, &tmp); // 1 /* mag 2 */
        secp256k1_fe_mul(&x1n, &d, &wd); /* mag 1 */
        secp256k1_fe_add(&x1n, &tmp); /* mag 3 */
        x2n = x1n; /* mag 3 */
        secp256k1_fe_add(&x2n, &wd); /* mag 5 */
        secp256k1_fe_negate(&x2n, &x2n); // 5 /* mag 6 */
        secp256k1_fe_mul(&x3d, &c, t); /* mag 1 */
        secp256k1_fe_sqr(&x3d, &x3d); /* mag 1 */
        secp256k1_fe_sqr(&x3n, &wd); /* mag 1 */
        secp256k1_fe_add(&x3n, &x3d); /* mag 2 */
        secp256k1_fe_mul(&jinv, &x3d, &wd); /* mag 1 */
        secp256k1_fe_inv(&jinv, &jinv); /* mag 1 */
        secp256k1_fe_mul(&x1, &x1n, &x3d); /* mag 1 */
        secp256k1_fe_mul(&x1, &x1, &jinv); /* mag 1 */
        secp256k1_fe_mul(&x2, &x2n, &x3d); /* mag 1 */
        secp256k1_fe_mul(&x2, &x2, &jinv); /* mag 1 */
        secp256k1_fe_mul(&x3, &x3n, &wd); /* mag 1 */
        secp256k1_fe_mul(&x3, &x3, &jinv); /* mag 1 */
    }

    {
        secp256k1_fe alphain, betain, gammain, y1, y2, y3;
        secp256k1_fe_sqr(&alphain, &x1); /* mag 1 */
        secp256k1_fe_mul(&alphain, &alphain, &x1); /* mag 1 */
        secp256k1_fe_add(&alphain, &b); /* mag 2 */
        secp256k1_fe_sqr(&betain, &x2); /* mag 1 */
        secp256k1_fe_mul(&betain, &betain, &x2); /* mag 1 */
        secp256k1_fe_add(&betain, &b); /* mag 2 */
        secp256k1_fe_sqr(&gammain, &x3); /* mag 1 */
        secp256k1_fe_mul(&gammain, &gammain, &x3); /* mag 1 */
        secp256k1_fe_add(&gammain, &b); /* mag 2 */
        alphaquad = secp256k1_fe_sqrt(&y1, &alphain);
        betaquad = secp256k1_fe_sqrt(&y2, &betain);
        secp256k1_fe_sqrt(&y3, &gammain);

        secp256k1_fe_cmov(&x1, &x2, (!alphaquad) & betaquad);
        secp256k1_fe_cmov(&y1, &y2, (!alphaquad) & betaquad);
        secp256k1_fe_cmov(&x1, &x3, (!alphaquad) & !betaquad);
        secp256k1_fe_cmov(&y1, &y3, (!alphaquad) & !betaquad);

        secp256k1_ge_set_xy(ge, &x1, &y1);
    }

    /* The linked algorithm from the paper uses the Jacobi symbol of t to
     * determine the Jacobi symbol of the produced y coordinate. Since the
     * rest of the algorithm only uses t^2, we can safely use another criterion
     * as long as negation of t results in negation of the y coordinate. Here
     * we choose to use t's oddness, as it is faster to determine. */
    secp256k1_fe_negate(&tmp, (secp256k1_fe*)&ge->n[GE_OFFSET_Y]); // 1
    secp256k1_fe_cmov((secp256k1_fe*)&ge->n[GE_OFFSET_Y], &tmp, secp256k1_fe_is_odd(t));
}

bool liquid_generator_generate(uint8_t gen[static LIQUID_GENERATOR_LEN],
                               const uint8_t seed32[static 32]) {
    static const uint8_t prefix1[17] = "1st generation: ";
    static const uint8_t prefix2[17] = "2nd generation: ";
    secp256k1_fe t;
    secp256k1_ge add;
    secp256k1_ge accum;
    cx_sha256_t sha256;

    bool result = false;
    BEGIN_TRY {
        TRY {
            cx_sha256_init(&sha256);
            crypto_hash_update(&sha256.header, prefix1, 16);
            crypto_hash_update(&sha256.header, seed32, 32);
            crypto_hash_digest(&sha256.header, t.n, sizeof(t.n));
            if(secp256k1_scalar_check_overflow(t.n)) {
                THROW(CX_OVERFLOW);
            }
            shallue_van_de_woestijne(&accum, &t);

            cx_sha256_init(&sha256);
            crypto_hash_update(&sha256.header, prefix2, 16);
            crypto_hash_update(&sha256.header, seed32, 32);
            crypto_hash_digest(&sha256.header, t.n, sizeof(t.n));
            if(secp256k1_scalar_check_overflow(t.n)) {
                THROW(CX_OVERFLOW);
            }
            shallue_van_de_woestijne(&add, &t);
            secp256k1_ge_add(&accum, &accum, &add);
            memcpy(gen, accum.n, sizeof(accum.n));

            result = true;
        }
        CATCH_ALL {
            result = false;
        }
        FINALLY {
            // Zeroize sensitive data here
        }
    }
    END_TRY;
    return result;
}

#ifdef IMPLEMENT_ON_DEVICE_TESTS
#include "liquid_proofs_tests.h"
#endif

#endif // HAVE_LIQUID