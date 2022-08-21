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
const uint8_t secp256k1_generator_h[] = {
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
bool secp256k1_scalar_check_overflow(const uint8_t a[static 32]) {
    return cx_math_cmp(a, secp256k1_scalar_max, 32) > 0;
}

/**
 * Sets a group element (affine) equal to the point with the given X coordinate and a Y coordinate
 * that is a quadratic residue modulo p.
 *
 * @param[out] r
 *   Resulting group element encoded as 04 x y.
 * @param[in] x
 *   X coordinate of a point.
 */
static void ge_set_xquad(uint8_t r[static 65], const uint8_t x[static 32]) {
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
static inline void ge_neg(uint8_t r[static 65], const uint8_t a[static 65]) {
    uint8_t *res_y = &r[1 + 32];
    const uint8_t *arg_y = &a[1 + 32];
    cx_math_sub(res_y, secp256k1_p, arg_y, 32);
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
    ge_set_xquad(ge, &commit[1]);
    if (commit[0] & 1) {
        ge_neg(ge, ge);
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
bool secp256k1_fe_is_quad_var(const uint8_t a[static 32]) {
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

bool liquid_rangeproof_verify_value(const uint8_t *proof,
                                    size_t plen,
                                    uint64_t value,
                                    const uint8_t *commit,
                                    size_t commit_len,
                                    const uint8_t generator[static 65]) {
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
    uint8_t tmp2[65];
    uint8_t tmpch[33];
    cx_sha256_t sha2;
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
                ge_neg(tmp, tmp);
                if(0 == cx_ecfp_add_point(CX_CURVE_SECP256K1, tmp, tmp, commitp, sizeof(tmp))) {
                    THROW(CX_EC_INFINITE_POINT);
                }
            } else {
                // Value is 0 thus we just keep commitment point "as is" because infinity point is
                // an identity element
                memcpy(tmp, commitp, sizeof(tmp));
            }


            // Now we just have a Schnorr signature in (e, s) form. The verification equation is:
            // e == H(sG - eX || proof params)

            // 1. Compute slow/overwrought commitment to proof params
            cx_sha256_init(&sha2);
            hash_update_point(&sha2.header, commitp);
            hash_update_point(&sha2.header, generator);
            crypto_hash_update(&sha2.header, proof, offset);
            crypto_hash_digest(&sha2.header, pp_comm, sizeof(pp_comm));

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
            if(0 == cx_ecfp_scalar_mult(CX_CURVE_SECP256K1, tmp, 65, es, 32)) {
                THROW(CX_EC_INFINITE_POINT);
            }
            memcpy(tmp2, secp256k1_generator, sizeof(tmp2));
            if(0 == cx_ecfp_scalar_mult(CX_CURVE_SECP256K1, tmp2, 65, ss, 32)) {
                THROW(CX_EC_INFINITE_POINT);
            }
            if(0 == cx_ecfp_add_point(CX_CURVE_SECP256K1, tmp, tmp, tmp2, 65)) {
                THROW(CX_EC_INFINITE_POINT);
            }
            crypto_get_compressed_pubkey(tmp, tmpch);

            // 2. Compute e = H(R || proof params)
            cx_sha256_init(&sha2);
            crypto_hash_update(&sha2.header, tmpch, 33);
            crypto_hash_update(&sha2.header, pp_comm, sizeof(pp_comm));
            crypto_hash_digest(&sha2.header, tmpch, sizeof(tmpch));

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

#endif // HAVE_LIQUID