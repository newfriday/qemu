/*
 * QEMU Kunpeng Accelerator Engine (KAE) cipher support
 *
 * Copyright (c) 2025 SmartX Inc
 *
 * Authors:
 *    Hyman Huang <yong.huang@smartx.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.  See the COPYING file in the
 * top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "qapi/error.h"
#include "crypto/cipher.h"
#include "cipherpriv.h"
#include "qemu/error-report.h"

#include <warpdrive/wd.h>
#include <warpdrive/wd_bmm.h>
#include <warpdrive/wd_cipher.h>

#define QCRYPTO_CIPHER_KAE_BLOCK_SIZE (4 * 1024)
#define QCRYPTO_CIPHER_KAE_BLOCK_NUM (4)
#define QCRYPTO_CIPHER_KAE_BLOCK_ALIGN_SIZE (64)

typedef struct QCryptoCipherKAE QCryptoCipherKAE;

struct QCryptoCipherKAE {
    QCryptoCipher base;

    uint8_t *key;
    size_t nkey;

    struct wd_queue queue;
    struct wd_blkpool_setup pool_setup;
    struct wcrypto_cipher_ctx_setup cipher_setup;

    void *pool;
    void *ctx;

    uint8_t *iv;
    size_t niv;
};

static bool
qcrypto_kae_cipher_supports(QCryptoCipherAlgorithm alg,
                            QCryptoCipherMode mode)
{
    switch (alg) {
    case QCRYPTO_CIPHER_ALGO_SM4:
    case QCRYPTO_CIPHER_ALGO_AES_128:
    case QCRYPTO_CIPHER_ALGO_AES_192:
    case QCRYPTO_CIPHER_ALGO_AES_256:
        break;
    default:
        return false;
    }

    /*
     * All modes (CTR, XTS, CBC, ECB) currently defined in
     * QEMU are supported by KAE
     */
    return true;
}

static void *
qcrypto_kae_cipher_alloc_blk(void *pool, size_t size)
{
    return wd_alloc_blk(pool);
}

static void
qcrypto_kae_cipher_free_blk(void *pool, void *blk)
{
    wd_free_blk(pool, blk);
}

static void *
qcrypto_kae_cipher_blk_iova_map(void *usr, void *va, size_t sz)
{
    return wd_blk_iova_map(usr, va);
}

static void
qcrypto_kae_cipher_blk_iova_unmap(void *usr, void *va,
                                 void *dma, size_t sz)
{
    return wd_blk_iova_unmap(usr, dma, va);
}

static enum wcrypto_cipher_mode
qcrypto_kae_cipher_mode_interpret(QCryptoCipherMode mode)
{
    switch (mode) {
    case QCRYPTO_CIPHER_MODE_ECB:
        return WCRYPTO_CIPHER_ECB;
    case QCRYPTO_CIPHER_MODE_CBC:
        return WCRYPTO_CIPHER_CBC;
    case QCRYPTO_CIPHER_MODE_XTS:
        return WCRYPTO_CIPHER_XTS;
    case QCRYPTO_CIPHER_MODE_CTR:
        return WCRYPTO_CIPHER_CTR;
    default:
        g_assert_not_reached();
    }
}

static enum wcrypto_cipher_mode
qcrypto_kae_cipher_algo_interpret(QCryptoCipherAlgorithm alg)
{
    switch (alg) {
    case QCRYPTO_CIPHER_ALGO_SM4:
        return WCRYPTO_CIPHER_SM4;
    case QCRYPTO_CIPHER_ALGO_AES_128:
    case QCRYPTO_CIPHER_ALGO_AES_192:
    case QCRYPTO_CIPHER_ALGO_AES_256:
        return WCRYPTO_CIPHER_AES;
    case QCRYPTO_CIPHER_ALGO_DES:
        return WCRYPTO_CIPHER_DES;
    case QCRYPTO_CIPHER_ALGO_3DES:
        return WCRYPTO_CIPHER_3DES;
    default:
        g_assert_not_reached();
    }
}

QCryptoCipher *
qcrypto_kae_cipher_ctx_new(QCryptoCipherAlgorithm alg,
                           QCryptoCipherMode mode,
                           const uint8_t *key,
                           size_t nkey,
                           Error **errp)
{
    QCryptoCipherKAE *kae;
    struct wd_queue *queue;
    struct wd_blkpool_setup *pool_setup;
    struct wcrypto_cipher_ctx_setup *cipher_setup;
    int ret;

    if (!qcrypto_kae_cipher_supports(alg, mode)) {
        return NULL;
    }

    kae = g_new0(QCryptoCipherKAE, 1);
    kae->key = g_new0(uint8_t, nkey);
    memcpy(kae->key, key, nkey);
    kae->nkey = nkey;

    queue = &kae->queue;
    pool_setup = &kae->pool_setup;
    cipher_setup = &kae->cipher_setup;

    queue->capa.alg = "cipher";
    ret = wd_request_queue(queue);
    if (ret < 0) {
        error_setg(errp, "Request wd queue failed with error code %d", ret);
        goto error;
    }

    pool_setup->block_size = QCRYPTO_CIPHER_KAE_BLOCK_SIZE;
    pool_setup->block_num = QCRYPTO_CIPHER_KAE_BLOCK_NUM;
    pool_setup->align_size = QCRYPTO_CIPHER_KAE_BLOCK_ALIGN_SIZE;

    kae->pool = wd_blkpool_create(queue, pool_setup);
    if (!kae->pool) {
        error_setg(errp, "Create wd blkpool failed");
        goto error_blkpool;
    }

    cipher_setup->br.alloc = qcrypto_kae_cipher_alloc_blk;
    cipher_setup->br.free = qcrypto_kae_cipher_free_blk;
    cipher_setup->br.iova_map = qcrypto_kae_cipher_blk_iova_map;
    cipher_setup->br.iova_unmap = qcrypto_kae_cipher_blk_iova_unmap;
    cipher_setup->br.usr = kae->pool;
    cipher_setup->alg = qcrypto_kae_cipher_algo_interpret(alg);
    cipher_setup->mode = qcrypto_kae_cipher_mode_interpret(mode);

    kae->ctx = wcrypto_create_cipher_ctx(queue, cipher_setup);
    if (!kae->ctx) {
        error_setg(errp, "Create wd cipher context failed");
        goto error_cipher_ctx;
    }

    wcrypto_set_cipher_key(kae->ctx, kae->key, kae->nkey);

    kae->base.alg = alg;
    kae->base.mode = mode;
    kae->base.driver = &qcrypto_cipher_kae_driver;
    return &kae->base;

 error_cipher_ctx:
    wd_blkpool_destroy(kae->pool);
 error_blkpool:
    wd_release_queue(&kae->queue);
 error:
    g_free(kae->key);
    g_free(kae);
    return NULL;
}

static int
qcrypto_kae_cipher_op(QCryptoCipherKAE *kae,
                      const void *in, void *out,
                      size_t len, bool do_encrypt,
                      Error **errp)
{
    struct wcrypto_cipher_op_data op_data;
    struct wcrypto_cipher_ctx_setup *cipher_setup;
    void *pool;
    int ret = -1;

    cipher_setup = &kae->cipher_setup;
    pool = kae->pool;

    memset(&op_data, 0, sizeof(op_data));
    op_data.op_type = do_encrypt ?
                      WCRYPTO_CIPHER_ENCRYPTION : WCRYPTO_CIPHER_DECRYPTION;

    op_data.iv = cipher_setup->br.alloc(pool, kae->niv);
    if (!op_data.iv) {
        error_setg(errp, "Alloc wd blk iv failed");
        goto end;
    }
    if (kae->iv) {
        memcpy(op_data.iv, kae->iv, kae->niv);
        op_data.iv_bytes = kae->niv;
    }

    op_data.in = cipher_setup->br.alloc(pool, len);
    if (!op_data.in) {
        error_setg(errp, "Alloc wd blk in failed");
        goto error_iv;
    }
    memcpy(op_data.in, in, len);
    op_data.in_bytes = len;

    op_data.out = cipher_setup->br.alloc(pool, len);
    if (!op_data.out) {
        error_setg(errp, "Alloc wd blk out failed");
        goto error_in;
    }
    op_data.out_bytes = len;

    if (wcrypto_do_cipher(kae->ctx, &op_data, NULL)) {
        error_setg(errp, "Wcrypto do cipher failed with error code %d", ret);
        goto error_out;
    }

    memcpy(out, op_data.out, len);
    ret = 0;

 error_out:
    cipher_setup->br.free(pool, op_data.out);
 error_in:
    cipher_setup->br.free(pool, op_data.in);
 error_iv:
    cipher_setup->br.free(pool, op_data.iv);
 end:
    return ret;
}

static int
qcrypto_kae_cipher_encrypt(QCryptoCipher *cipher, const void *in,
                           void *out, size_t len, Error **errp)
{
    QCryptoCipherKAE *kae = container_of(cipher, QCryptoCipherKAE, base);
    return qcrypto_kae_cipher_op(kae, in, out, len, true, errp);
}

static int
qcrypto_kae_cipher_decrypt(QCryptoCipher *cipher, const void *in,
                           void *out, size_t len, Error **errp)
{
    QCryptoCipherKAE *kae = container_of(cipher, QCryptoCipherKAE, base);
    return qcrypto_kae_cipher_op(kae, in, out, len, false, errp);
}

static int
qcrypto_kae_cipher_setiv(QCryptoCipher *cipher,
                         const uint8_t *iv, size_t niv,
                         Error **errp)
{
    QCryptoCipherKAE *kae = container_of(cipher, QCryptoCipherKAE, base);

    if (kae->niv != niv) {
        g_free(kae->iv);
        kae->iv = g_new0(uint8_t, niv);
        kae->niv = niv;
    }
    memcpy(kae->iv, iv, niv);

    return 0;
}

static void
qcrypto_kae_cipher_do_free(QCryptoCipherKAE *kae)
{
    g_assert(kae != NULL);

    wcrypto_del_cipher_ctx(kae->ctx);
    wd_blkpool_destroy(kae->pool);
    wd_release_queue(&kae->queue);
    g_free(kae->key);
    g_free(kae->iv);
}

static void
qcrypto_kae_cipher_free(QCryptoCipher *cipher)
{
    QCryptoCipherKAE *kae = container_of(cipher, QCryptoCipherKAE, base);
    qcrypto_kae_cipher_do_free(kae);
    g_free(kae);
}

static const struct QCryptoCipherDriver qcrypto_cipher_kae_driver = {
    .cipher_encrypt = qcrypto_kae_cipher_encrypt,
    .cipher_decrypt = qcrypto_kae_cipher_decrypt,
    .cipher_setiv = qcrypto_kae_cipher_setiv,
    .cipher_free = qcrypto_kae_comm_ctx_free,
};
