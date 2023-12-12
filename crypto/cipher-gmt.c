/*
 * QEMU Crypto GM/T 0018-2012 standard cipher support
 *
 * Copyright (c) 2024 SmartX Inc
 *
 * Authors:
 *    Hyman Huang <yong.huang@smartx.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.  See the COPYING file in the
 * top-level directory.
 */

#include <swsds.h>

#include "qapi/error.h"
#include "crypto/cipher.h"
#include "cipherpriv.h"

static const struct QCryptoCipherDriver qcrypto_cipher_gmt_driver;

QCryptoCipher *
qcrypto_gmt_cipher_ctx_new(QCryptoCipherAlgorithm alg,
                           QCryptoCipherMode mode,
                           const uint8_t *key,
                           size_t nkey, Error **errp)
{
    return NULL;
}

static int
qcrypto_gmt_cipher_setiv(QCryptoCipher *cipher,
                         const uint8_t *iv,
                         size_t niv, Error **errp)
{
    return 0;
}

static int
qcrypto_gmt_cipher_encrypt(QCryptoCipher *cipher,
                           const void *in, void *out,
                           size_t len, Error **errp)
{
    return 0;
}

static int
qcrypto_gmt_cipher_decrypt(QCryptoCipher *cipher,
                           const void *in, void *out,
                           size_t len, Error **errp)
{
    return 0;
}

static void qcrypto_gmt_comm_ctx_free(QCryptoCipher *cipher)
{

}

static const struct QCryptoCipherDriver qcrypto_cipher_gmt_driver = {
    .cipher_encrypt = qcrypto_gmt_cipher_encrypt,
    .cipher_decrypt = qcrypto_gmt_cipher_decrypt,
    .cipher_setiv = qcrypto_gmt_cipher_setiv,
    .cipher_free = qcrypto_gmt_comm_ctx_free,
};
