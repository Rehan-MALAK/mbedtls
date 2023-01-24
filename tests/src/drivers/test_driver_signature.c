/*
 * Test driver for signature functions.
 * Currently supports signing and verifying precalculated hashes, using
 * only deterministic ECDSA on curves secp256r1, secp384r1 and secp521r1.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <test/helpers.h>

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS) && defined(PSA_CRYPTO_DRIVER_TEST)
#include "psa/crypto.h"
#include "psa_crypto_core.h"
#include "psa_crypto_ecp.h"
#include "psa_crypto_hash.h"
#include "psa_crypto_rsa.h"
#include "mbedtls/ecp.h"

#include "test/drivers/hash.h"
#include "test/drivers/signature.h"
#include "test/drivers/hash.h"

#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"

#include "test/random.h"

#if defined(MBEDTLS_TEST_LIBTESTDRIVER1)
#include "libtestdriver1/library/psa_crypto_ecp.h"
#include "libtestdriver1/library/psa_crypto_hash.h"
#include "libtestdriver1/library/psa_crypto_rsa.h"
#endif

#include <string.h>

mbedtls_test_driver_signature_hooks_t
    mbedtls_test_driver_signature_sign_hooks = MBEDTLS_TEST_DRIVER_SIGNATURE_INIT;
mbedtls_test_driver_signature_hooks_t
    mbedtls_test_driver_signature_verify_hooks = MBEDTLS_TEST_DRIVER_SIGNATURE_INIT;

psa_status_t sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length)
{
    if (attributes->core.type == PSA_KEY_TYPE_RSA_KEY_PAIR) {
        if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) ||
            PSA_ALG_IS_RSA_PSS(alg)) {
#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
            (defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
            defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS))
            return libtestdriver1_mbedtls_psa_rsa_sign_hash(
                (const libtestdriver1_psa_key_attributes_t *) attributes,
                key_buffer, key_buffer_size,
                alg, hash, hash_length,
                signature, signature_size, signature_length);
#elif defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
            defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS)
            return mbedtls_psa_rsa_sign_hash(
                attributes,
                key_buffer, key_buffer_size,
                alg, hash, hash_length,
                signature, signature_size, signature_length);
#endif
        } else {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else if (PSA_KEY_TYPE_IS_ECC(attributes->core.type)) {
        if (PSA_ALG_IS_ECDSA(alg)) {
#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
            (defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
            defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA))
            return libtestdriver1_mbedtls_psa_ecdsa_sign_hash(
                (const libtestdriver1_psa_key_attributes_t *) attributes,
                key_buffer, key_buffer_size,
                alg, hash, hash_length,
                signature, signature_size, signature_length);
#elif defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
            defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
            return mbedtls_psa_ecdsa_sign_hash(
                attributes,
                key_buffer, key_buffer_size,
                alg, hash, hash_length,
                signature, signature_size, signature_length);
#endif
        } else {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash,
    size_t hash_length,
    const uint8_t *signature,
    size_t signature_length)
{
    if (PSA_KEY_TYPE_IS_RSA(attributes->core.type)) {
        if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) ||
            PSA_ALG_IS_RSA_PSS(alg)) {
#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
            (defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
            defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS))
            return libtestdriver1_mbedtls_psa_rsa_verify_hash(
                (const libtestdriver1_psa_key_attributes_t *) attributes,
                key_buffer, key_buffer_size,
                alg, hash, hash_length,
                signature, signature_length);
#elif defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PKCS1V15_SIGN) || \
            defined(MBEDTLS_PSA_BUILTIN_ALG_RSA_PSS)
            return mbedtls_psa_rsa_verify_hash(
                attributes,
                key_buffer, key_buffer_size,
                alg, hash, hash_length,
                signature, signature_length);
#endif
        } else {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else if (PSA_KEY_TYPE_IS_ECC(attributes->core.type)) {
        if (PSA_ALG_IS_ECDSA(alg)) {
#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
            (defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
            defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA))
            return libtestdriver1_mbedtls_psa_ecdsa_verify_hash(
                (const libtestdriver1_psa_key_attributes_t *) attributes,
                key_buffer, key_buffer_size,
                alg, hash, hash_length,
                signature, signature_length);
#elif defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
            defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
            return mbedtls_psa_ecdsa_verify_hash(
                attributes,
                key_buffer, key_buffer_size,
                alg, hash, hash_length,
                signature, signature_length);
#endif
        } else {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t mbedtls_test_transparent_signature_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t hash_length;
    uint8_t hash[PSA_HASH_MAX_SIZE];

    ++mbedtls_test_driver_signature_sign_hooks.hits;

    if (mbedtls_test_driver_signature_sign_hooks.forced_status != PSA_SUCCESS) {
        return mbedtls_test_driver_signature_sign_hooks.forced_status;
    }

    if (mbedtls_test_driver_signature_sign_hooks.forced_output != NULL) {
        if (mbedtls_test_driver_signature_sign_hooks.forced_output_length > signature_size) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }

        memcpy(signature, mbedtls_test_driver_signature_sign_hooks.forced_output,
               mbedtls_test_driver_signature_sign_hooks.forced_output_length);
        *signature_length = mbedtls_test_driver_signature_sign_hooks.forced_output_length;

        return PSA_SUCCESS;
    }

#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_HASH)
    status = libtestdriver1_mbedtls_psa_hash_compute(
        PSA_ALG_SIGN_GET_HASH(alg), input, input_length,
        hash, sizeof(hash), &hash_length);
#elif defined(MBEDTLS_PSA_BUILTIN_HASH)
    status = mbedtls_psa_hash_compute(
        PSA_ALG_SIGN_GET_HASH(alg), input, input_length,
        hash, sizeof(hash), &hash_length);
#else
    (void) input;
    (void) input_length;
    status = PSA_ERROR_NOT_SUPPORTED;
#endif
    if (status != PSA_SUCCESS) {
        return status;
    }

    return sign_hash(attributes, key_buffer, key_buffer_size,
                     alg, hash, hash_length,
                     signature, signature_size, signature_length);
}

psa_status_t mbedtls_test_opaque_signature_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key,
    size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t mbedtls_test_transparent_signature_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    const uint8_t *signature,
    size_t signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t hash_length;
    uint8_t hash[PSA_HASH_MAX_SIZE];

    ++mbedtls_test_driver_signature_verify_hooks.hits;

    if (mbedtls_test_driver_signature_verify_hooks.forced_status != PSA_SUCCESS) {
        return mbedtls_test_driver_signature_verify_hooks.forced_status;
    }

#if defined(MBEDTLS_TEST_LIBTESTDRIVER1) && \
    defined(LIBTESTDRIVER1_MBEDTLS_PSA_BUILTIN_HASH)
    status = libtestdriver1_mbedtls_psa_hash_compute(
        PSA_ALG_SIGN_GET_HASH(alg), input, input_length,
        hash, sizeof(hash), &hash_length);
#elif defined(MBEDTLS_PSA_BUILTIN_HASH)
    status = mbedtls_psa_hash_compute(
        PSA_ALG_SIGN_GET_HASH(alg), input, input_length,
        hash, sizeof(hash), &hash_length);
#else
    (void) input;
    (void) input_length;
    status = PSA_ERROR_NOT_SUPPORTED;
#endif
    if (status != PSA_SUCCESS) {
        return status;
    }

    return verify_hash(attributes, key_buffer, key_buffer_size,
                       alg, hash, hash_length,
                       signature, signature_length);
}

psa_status_t mbedtls_test_opaque_signature_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key,
    size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    const uint8_t *signature,
    size_t signature_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) signature;
    (void) signature_length;

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t mbedtls_test_transparent_signature_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    ++mbedtls_test_driver_signature_sign_hooks.hits;

    if (mbedtls_test_driver_signature_sign_hooks.forced_status != PSA_SUCCESS) {
        return mbedtls_test_driver_signature_sign_hooks.forced_status;
    }

    if (mbedtls_test_driver_signature_sign_hooks.forced_output != NULL) {
        if (mbedtls_test_driver_signature_sign_hooks.forced_output_length > signature_size) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        memcpy(signature, mbedtls_test_driver_signature_sign_hooks.forced_output,
               mbedtls_test_driver_signature_sign_hooks.forced_output_length);
        *signature_length = mbedtls_test_driver_signature_sign_hooks.forced_output_length;
        return PSA_SUCCESS;
    }

    return sign_hash(attributes, key_buffer, key_buffer_size,
                     alg, hash, hash_length,
                     signature, signature_size, signature_length);
}

#define PSA_CRYPTO_TEST_DRIVER_BUILTIN_ECDSA_KEY_SLOT   1
static const uint8_t mbedtls_test_driver_ecdsa_key[32] =
{ 0xdc, 0x7d, 0x9d, 0x26, 0xd6, 0x7a, 0x4f, 0x63,
  0x2c, 0x34, 0xc2, 0xdc, 0x0b, 0x69, 0x86, 0x18,
  0x38, 0x82, 0xc2, 0x06, 0xdf, 0x04, 0xcd, 0xb7,
  0xd6, 0x9a, 0xab, 0xe2, 0x8b, 0xe4, 0xf8, 0x1a };
psa_status_t mbedtls_test_opaque_signature_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;

    if (key_length == sizeof(psa_drv_slot_number_t)) {
        /* Assume this is a builtin key based on the key material length. */
        psa_drv_slot_number_t slot_number = *((psa_drv_slot_number_t *) key);
        switch (slot_number) {
        case PSA_CRYPTO_TEST_DRIVER_BUILTIN_ECDSA_KEY_SLOT:
            /* This is the ECDSA slot. Verify the key's attributes before
             * returning the public key. */
            if (psa_get_key_type(attributes) !=
                PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
                return PSA_ERROR_CORRUPTION_DETECTED;
            }
            if (psa_get_key_bits(attributes) != 256) {
                return PSA_ERROR_CORRUPTION_DETECTED;
            }
            if (psa_get_key_algorithm(attributes) !=
                PSA_ALG_ECDSA(PSA_ALG_ANY_HASH)) {
                return PSA_ERROR_CORRUPTION_DETECTED;
            }

            if (signature_size < PSA_ECDSA_SIGNATURE_SIZE(256)) {
                return PSA_ERROR_BUFFER_TOO_SMALL;
            }

            return( psa_sign_hash_builtin( attributes,
                                           mbedtls_test_driver_ecdsa_key,
                                           sizeof(mbedtls_test_driver_ecdsa_key),
                                           alg,
                                           hash,
                                           hash_length,
                                           signature,
                                           signature_size,
                                           signature_length ) );
        default:
            return PSA_ERROR_DOES_NOT_EXIST;
        }
    }
    return PSA_ERROR_CORRUPTION_DETECTED;
}

psa_status_t mbedtls_test_transparent_signature_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length)
{
    ++mbedtls_test_driver_signature_verify_hooks.hits;

    if (mbedtls_test_driver_signature_verify_hooks.forced_status != PSA_SUCCESS) {
        return mbedtls_test_driver_signature_verify_hooks.forced_status;
    }

    return verify_hash(attributes, key_buffer, key_buffer_size,
                       alg, hash, hash_length,
                       signature, signature_length);
}

psa_status_t mbedtls_test_opaque_signature_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length)
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
