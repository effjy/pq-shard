/*
 * share.c - PQ-Shard share-file format + post-quantum sealing. See share.h.
 *
 * Share blob layout (all integers little-endian):
 *
 *   offset  size  field
 *   ------  ----  -----------------------------------------------------------
 *   0       8     magic  "PQSHARD\0"
 *   8       1     format_version (1)
 *   9       1     flags  (bit0 = sealed, bit1 = secret_is_text)
 *   10      1     k  (threshold)
 *   11      1     n  (total shares, informational)
 *   12      1     x  (this share's x-coordinate, 1..n)
 *   13      3     reserved (0)
 *   16      16    set_id  (random; ties a split's shares together)
 *   32      4     secret_len
 *   36      4     mlen     (= secret_len + VERIFY_TAG_LEN; the y-material len)
 *   40      ...   body (plain or sealed, see below)
 *
 * The "material" that Shamir actually splits is
 *     M = secret || BLAKE2b(set_id || secret)[:16]
 * so the verification tag is itself secret-shared: it discloses nothing below
 * the threshold, yet lets a reconstruction be checked. mlen = |M|.
 *
 * Plain body (flags.sealed == 0):
 *   40        mlen   y-material (this share's evaluations)
 *   40+mlen   32     BLAKE2b-256 over bytes [0, 40+mlen)  -- file integrity
 *
 * Sealed body (flags.sealed == 1): the y-material is encrypted just like a
 * Ciphers hybrid file. The 40-byte header is bound as associated data, so the
 * AEAD tag also authenticates k/n/x/set_id/secret_len.
 *   40        16    argon2 salt
 *   56        4     argon2 t_cost
 *   60        4     argon2 m_cost
 *   64        4     argon2 parallelism
 *   68        HB    hybrid block (wrap nonce || wrapped sk || KEM ciphertext)
 *   68+HB     24    XChaCha20-Poly1305 nonce
 *   68+HB+24  mlen+16   AEAD(y-material) + tag
 */
#include "share.h"
#include "shamir.h"
#include "hybrid_kem.h"

#include <sodium.h>
#include <argon2.h>

#include <string.h>
#include <stdlib.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define MAGIC          "PQSHARD\0"
#define MAGIC_LEN      8
#define FORMAT_VERSION 1
#define HDR_LEN        40
#define SET_ID_LEN     16
#define VERIFY_TAG_LEN 16
#define PLAIN_HASH_LEN 32

#define FLAG_SEALED    0x01
#define FLAG_TEXT      0x02

/* Sealed-mode crypto sizes (XChaCha20-Poly1305 + Argon2id). */
#define SALT_LEN       16
#define MASTERKEY_LEN  crypto_aead_xchacha20poly1305_ietf_KEYBYTES   /* 32 */
#define AEAD_NONCE_LEN crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  /* 24 */
#define AEAD_ABYTES    crypto_aead_xchacha20poly1305_ietf_ABYTES     /* 16 */
#define WRAP_NONCE_LEN AEAD_NONCE_LEN
#define WRAPPED_SK_LEN (HK_SK_LEN + AEAD_ABYTES)
#define HYBRID_BLOCK_LEN (WRAP_NONCE_LEN + WRAPPED_SK_LEN + HK_KEM_CT_LEN)
#define WRAP_AD        ((const unsigned char *)"PQSHARD-HYBRID-WRAP")
#define WRAP_AD_LEN    19

/* Sealed-body fixed header (after the common 40-byte header, before the AEAD
 * ciphertext): salt(16) + t/m/p (12) + hybrid block + aead nonce. */
#define SEALED_PREFIX_LEN (SALT_LEN + 12 + HYBRID_BLOCK_LEN + AEAD_NONCE_LEN)

/* Untrusted-header KDF bounds (cover STRONG: 4 GiB / t=4 / 8 lanes). */
#define MAX_KDF_M_COST    (4u * 1024u * 1024u)
#define MAX_KDF_T_COST    16u
#define MAX_KDF_PARALLEL  16u

/* ----- little-endian helpers ------------------------------------------- */

static void put_u32(uint8_t *b, uint32_t v) {
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff; b[3] = (v >> 24) & 0xff;
}
static uint32_t get_u32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static void seterr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) snprintf(err, errlen, "%s", msg);
}

/* ----- KDF -------------------------------------------------------------- */

typedef struct { uint32_t t_cost, m_cost, parallelism; } kdf_params_t;

static void kdf_params_for_level(kdf_level_t level, kdf_params_t *p) {
    switch (level) {
    case KDF_BASIC:
        p->t_cost = 3; p->m_cost = 256u * 1024u;      p->parallelism = 4; break;
    case KDF_STRONG:
        p->t_cost = 4; p->m_cost = 4u * 1024u * 1024u; p->parallelism = 8; break;
    case KDF_MEDIUM:
    default:
        p->t_cost = 3; p->m_cost = 1u * 1024u * 1024u; p->parallelism = 4; break;
    }
}

static int derive_key(const char *password, const uint8_t *salt,
                      const kdf_params_t *p, uint8_t *key, size_t key_len) {
    int rc = argon2id_hash_raw(p->t_cost, p->m_cost, p->parallelism,
                               password, strlen(password),
                               salt, SALT_LEN, key, key_len);
    return rc == ARGON2_OK ? 0 : -1;
}

/* ----- hybrid wrap helpers (mirrors Ciphers crypto.c) ------------------- */

/* Build a hybrid block and the 32-byte AEAD key: generate a fresh hybrid
 * keypair, wrap its secret key with the password-derived master key, and
 * encapsulate to its public key. Returns 0 on success. */
static int hybrid_build(const char *password, const uint8_t *salt,
                        const kdf_params_t *kp,
                        uint8_t block[HYBRID_BLOCK_LEN],
                        uint8_t file_key[HK_SHARED_SECRET_LEN]) {
    uint8_t master[MASTERKEY_LEN];
    uint8_t kyber_pk[HK_KYBER_PUBLICKEYBYTES], x448_pk[HK_X448_PUBKEY_LEN];
    uint8_t hybrid_sk[HK_SK_LEN];
    int ret = -1;

    sodium_mlock(master, sizeof(master));
    sodium_mlock(hybrid_sk, sizeof(hybrid_sk));

    if (derive_key(password, salt, kp, master, sizeof(master)) != 0) goto out;
    if (hk_generate_keypair(kyber_pk, hybrid_sk,
                            x448_pk, hybrid_sk + HK_KYBER_SECRETKEYBYTES) != 0) goto out;

    uint8_t *wrap_nonce = block;
    uint8_t *wrapped_sk = wrap_nonce + WRAP_NONCE_LEN;
    uint8_t *kem_ct     = wrapped_sk + WRAPPED_SK_LEN;

    randombytes_buf(wrap_nonce, WRAP_NONCE_LEN);
    crypto_aead_xchacha20poly1305_ietf_encrypt(wrapped_sk, NULL,
        hybrid_sk, HK_SK_LEN, WRAP_AD, WRAP_AD_LEN, NULL, wrap_nonce, master);

    if (hk_encapsulate(file_key, kem_ct, kyber_pk, x448_pk) != 0) goto out;
    ret = 0;
out:
    sodium_munlock(master, sizeof(master));
    sodium_munlock(hybrid_sk, sizeof(hybrid_sk));
    return ret;
}

/* Recover the 32-byte AEAD key from a hybrid block. Returns 0 on success
 * (a wrong password is caught by the wrap tag). */
static int hybrid_open(const char *password, const uint8_t *salt,
                       const kdf_params_t *kp,
                       const uint8_t block[HYBRID_BLOCK_LEN],
                       uint8_t file_key[HK_SHARED_SECRET_LEN]) {
    uint8_t master[MASTERKEY_LEN];
    uint8_t hybrid_sk[HK_SK_LEN];
    int ret = -1;

    sodium_mlock(master, sizeof(master));
    sodium_mlock(hybrid_sk, sizeof(hybrid_sk));

    const uint8_t *wrap_nonce = block;
    const uint8_t *wrapped_sk = wrap_nonce + WRAP_NONCE_LEN;
    const uint8_t *kem_ct     = wrapped_sk + WRAPPED_SK_LEN;

    if (derive_key(password, salt, kp, master, sizeof(master)) != 0) goto out;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(hybrid_sk, NULL, NULL,
            wrapped_sk, WRAPPED_SK_LEN, WRAP_AD, WRAP_AD_LEN, wrap_nonce, master) != 0)
        goto out;
    if (hk_decapsulate(file_key, kem_ct, hybrid_sk,
                       hybrid_sk + HK_KYBER_SECRETKEYBYTES) != 0) goto out;
    ret = 0;
out:
    sodium_munlock(master, sizeof(master));
    sodium_munlock(hybrid_sk, sizeof(hybrid_sk));
    return ret;
}

/* ----- verification tag ------------------------------------------------- */

/* tag = BLAKE2b(set_id || secret) truncated to VERIFY_TAG_LEN. */
static void compute_tag(const uint8_t set_id[SET_ID_LEN],
                        const uint8_t *secret, size_t secret_len,
                        uint8_t tag[VERIFY_TAG_LEN]) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, NULL, 0, VERIFY_TAG_LEN);
    crypto_generichash_update(&st, set_id, SET_ID_LEN);
    crypto_generichash_update(&st, secret, secret_len);
    crypto_generichash_final(&st, tag, VERIFY_TAG_LEN);
}

/* ----- init ------------------------------------------------------------- */

int pqshard_init(void) {
    if (sodium_init() < 0) return -1;
    struct rlimit rl = { 0, 0 };
    setrlimit(RLIMIT_CORE, &rl);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
    return 0;
}

/* ----- header (de)serialisation ----------------------------------------- */

static void write_header(uint8_t *hdr, int sealed, int is_text,
                         int k, int n, int x, const uint8_t set_id[SET_ID_LEN],
                         uint32_t secret_len, uint32_t mlen) {
    memset(hdr, 0, HDR_LEN);
    memcpy(hdr, MAGIC, MAGIC_LEN);
    hdr[8] = FORMAT_VERSION;
    hdr[9] = (uint8_t)((sealed ? FLAG_SEALED : 0) | (is_text ? FLAG_TEXT : 0));
    hdr[10] = (uint8_t)k;
    hdr[11] = (uint8_t)n;
    hdr[12] = (uint8_t)x;
    memcpy(hdr + 16, set_id, SET_ID_LEN);
    put_u32(hdr + 32, secret_len);
    put_u32(hdr + 36, mlen);
}

int pqshard_inspect(const uint8_t *blob, size_t len, share_info_t *info,
                    char *err, size_t errlen) {
    if (len < HDR_LEN || memcmp(blob, MAGIC, MAGIC_LEN) != 0) {
        seterr(err, errlen, "Not a PQ-Shard share (bad magic)."); return -1;
    }
    if (blob[8] != FORMAT_VERSION) {
        seterr(err, errlen, "Unsupported share format version."); return -1;
    }
    info->version    = blob[8];
    info->sealed     = (blob[9] & FLAG_SEALED) ? 1 : 0;
    info->is_text    = (blob[9] & FLAG_TEXT) ? 1 : 0;
    info->k          = blob[10];
    info->n          = blob[11];
    info->x          = blob[12];
    memcpy(info->set_id, blob + 16, SET_ID_LEN);
    info->secret_len = get_u32(blob + 32);
    uint32_t mlen    = get_u32(blob + 36);

    if (info->k < PQSHARD_MIN_K || info->x < 1 || info->x > PQSHARD_MAX_N ||
        info->secret_len == 0 || info->secret_len > PQSHARD_MAX_SECRET ||
        mlen != info->secret_len + VERIFY_TAG_LEN) {
        seterr(err, errlen, "Corrupt share header."); return -1;
    }

    /* Bounds-check the declared body against the actual blob length. */
    size_t need = info->sealed
        ? (size_t)HDR_LEN + SEALED_PREFIX_LEN + mlen + AEAD_ABYTES
        : (size_t)HDR_LEN + mlen + PLAIN_HASH_LEN;
    if (len != need) {
        seterr(err, errlen, "Share file has the wrong length (truncated or corrupt).");
        return -1;
    }
    return 0;
}

/* ----- split ------------------------------------------------------------ */

int pqshard_split(const uint8_t *secret, size_t secret_len, int is_text,
                  int n, int k, const char *passphrase, kdf_level_t level,
                  uint8_t **out_blobs, size_t *out_lens,
                  char *err, size_t errlen) {
    if (secret_len == 0) { seterr(err, errlen, "The secret is empty."); return -1; }
    if (secret_len > PQSHARD_MAX_SECRET) {
        seterr(err, errlen, "Secret is too large (over 64 MiB)."); return -1;
    }
    if (k < PQSHARD_MIN_K || n < k || n > PQSHARD_MAX_N) {
        seterr(err, errlen, "Need 2 <= threshold <= shares <= 255."); return -1;
    }
    int sealed = (passphrase && *passphrase) ? 1 : 0;

    int ret = -1;
    size_t mlen = secret_len + VERIFY_TAG_LEN;

    uint8_t set_id[SET_ID_LEN];
    randombytes_buf(set_id, sizeof(set_id));

    /* Material to split: secret || verification tag. */
    uint8_t *material = malloc(mlen);
    uint8_t **ys = calloc((size_t)n, sizeof(*ys));
    uint8_t *xs = malloc((size_t)n);
    if (!material || !ys || !xs) { seterr(err, errlen, "Out of memory."); goto cleanup; }
    sodium_mlock(material, mlen);
    memcpy(material, secret, secret_len);
    compute_tag(set_id, secret, secret_len, material + secret_len);

    for (int i = 0; i < n; i++) {
        ys[i] = malloc(mlen);
        if (!ys[i]) { seterr(err, errlen, "Out of memory."); goto cleanup; }
        sodium_mlock(ys[i], mlen);
    }
    if (shamir_split(material, mlen, n, k, xs, ys) != 0) {
        seterr(err, errlen, "Secret splitting failed."); goto cleanup;
    }

    kdf_params_t kp;
    kdf_params_for_level(level, &kp);

    for (int i = 0; i < n; i++) {
        uint8_t hdr[HDR_LEN];
        write_header(hdr, sealed, is_text, k, n, (int)xs[i], set_id,
                     (uint32_t)secret_len, (uint32_t)mlen);

        if (!sealed) {
            size_t blen = HDR_LEN + mlen + PLAIN_HASH_LEN;
            uint8_t *blob = malloc(blen);
            if (!blob) { seterr(err, errlen, "Out of memory."); goto cleanup; }
            memcpy(blob, hdr, HDR_LEN);
            memcpy(blob + HDR_LEN, ys[i], mlen);
            /* Unkeyed hash over the share's own bytes: detects accidental
             * corruption of a single share file. (Reveals nothing extra: the
             * share material itself is already information-theoretically safe
             * below the threshold.) */
            crypto_generichash(blob + HDR_LEN + mlen, PLAIN_HASH_LEN,
                               blob, HDR_LEN + mlen, NULL, 0);
            out_blobs[i] = blob;
            out_lens[i] = blen;
        } else {
            size_t blen = HDR_LEN + SEALED_PREFIX_LEN + mlen + AEAD_ABYTES;
            uint8_t *blob = malloc(blen);
            if (!blob) { seterr(err, errlen, "Out of memory."); goto cleanup; }
            memcpy(blob, hdr, HDR_LEN);

            uint8_t *p = blob + HDR_LEN;
            uint8_t *salt = p;                 p += SALT_LEN;
            put_u32(p, kp.t_cost);             p += 4;
            put_u32(p, kp.m_cost);             p += 4;
            put_u32(p, kp.parallelism);        p += 4;
            uint8_t *hblock = p;               p += HYBRID_BLOCK_LEN;
            uint8_t *nonce = p;                p += AEAD_NONCE_LEN;
            uint8_t *ct = p;                   /* mlen + tag */

            randombytes_buf(salt, SALT_LEN);
            randombytes_buf(nonce, AEAD_NONCE_LEN);

            uint8_t file_key[HK_SHARED_SECRET_LEN];
            sodium_mlock(file_key, sizeof(file_key));
            if (hybrid_build(passphrase, salt, &kp, hblock, file_key) != 0) {
                sodium_munlock(file_key, sizeof(file_key));
                free(blob);
                seterr(err, errlen, "Hybrid key setup failed (KDF memory or crypto error).");
                goto cleanup;
            }
            /* Encrypt the share material, binding the cleartext header. */
            crypto_aead_xchacha20poly1305_ietf_encrypt(ct, NULL,
                ys[i], mlen, blob, HDR_LEN, NULL, nonce, file_key);
            sodium_munlock(file_key, sizeof(file_key));

            out_blobs[i] = blob;
            out_lens[i] = blen;
        }
    }
    ret = 0;

cleanup:
    if (material) { sodium_munlock(material, mlen); free(material); }
    if (ys) {
        for (int i = 0; i < n; i++)
            if (ys[i]) { sodium_munlock(ys[i], mlen); free(ys[i]); }
        free(ys);
    }
    free(xs);
    /* On failure, release any blobs already produced so the caller never sees
     * a partially filled array. */
    if (ret != 0) {
        for (int i = 0; i < n; i++) {
            if (out_blobs[i]) { free(out_blobs[i]); out_blobs[i] = NULL; }
            out_lens[i] = 0;
        }
    }
    return ret;
}

/* ----- combine ---------------------------------------------------------- */

/* Recover one share's y-material (mlen bytes) into `ys_out`, which must be
 * mlen bytes. For sealed shares this needs the passphrase. Returns 0 on
 * success. */
static int recover_material(const uint8_t *blob, size_t len,
                            const share_info_t *info, size_t mlen,
                            const char *passphrase,
                            uint8_t *ys_out, char *err, size_t errlen) {
    if (!info->sealed) {
        const uint8_t *stored_hash = blob + HDR_LEN + mlen;
        uint8_t calc[PLAIN_HASH_LEN];
        crypto_generichash(calc, PLAIN_HASH_LEN, blob, HDR_LEN + mlen, NULL, 0);
        if (sodium_memcmp(calc, stored_hash, PLAIN_HASH_LEN) != 0) {
            seterr(err, errlen, "A share file is corrupted (integrity check failed).");
            return -1;
        }
        memcpy(ys_out, blob + HDR_LEN, mlen);
        return 0;
    }

    if (!passphrase || !*passphrase) {
        seterr(err, errlen, "These shares are sealed; a passphrase is required.");
        return -1;
    }
    const uint8_t *p = blob + HDR_LEN;
    const uint8_t *salt = p;                  p += SALT_LEN;
    kdf_params_t kp;
    kp.t_cost = get_u32(p);                    p += 4;
    kp.m_cost = get_u32(p);                    p += 4;
    kp.parallelism = get_u32(p);               p += 4;
    const uint8_t *hblock = p;                 p += HYBRID_BLOCK_LEN;
    const uint8_t *nonce = p;                  p += AEAD_NONCE_LEN;
    const uint8_t *ct = p;                     /* mlen + tag */

    if (kp.t_cost == 0 || kp.t_cost > MAX_KDF_T_COST ||
        kp.parallelism == 0 || kp.parallelism > MAX_KDF_PARALLEL ||
        kp.m_cost < 8u * kp.parallelism || kp.m_cost > MAX_KDF_M_COST) {
        seterr(err, errlen, "Invalid or unsafe KDF parameters in a share."); return -1;
    }

    uint8_t file_key[HK_SHARED_SECRET_LEN];
    sodium_mlock(file_key, sizeof(file_key));
    if (hybrid_open(passphrase, salt, &kp, hblock, file_key) != 0) {
        sodium_munlock(file_key, sizeof(file_key));
        seterr(err, errlen, "Wrong passphrase or a tampered share.");
        return -1;
    }
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(ys_out, NULL, NULL,
        ct, mlen + AEAD_ABYTES, blob, HDR_LEN, nonce, file_key);
    sodium_munlock(file_key, sizeof(file_key));
    if (rc != 0) {
        seterr(err, errlen, "Wrong passphrase or a tampered share.");
        return -1;
    }
    (void)len;
    return 0;
}

int pqshard_combine(const uint8_t **blobs, const size_t *lens, int nblobs,
                    const char *passphrase,
                    uint8_t **out_secret, size_t *out_secret_len,
                    int *out_is_text, char *err, size_t errlen) {
    if (nblobs < PQSHARD_MIN_K) {
        seterr(err, errlen, "Need at least two shares."); return -1;
    }

    /* Inspect every share; they must all parse, agree on set_id / threshold /
     * secret_len, and carry distinct x-coordinates. */
    share_info_t first;
    if (pqshard_inspect(blobs[0], lens[0], &first, err, errlen) != 0) return -1;

    int k = first.k;
    size_t secret_len = first.secret_len;
    size_t mlen = secret_len + VERIFY_TAG_LEN;

    if (nblobs < k) {
        snprintf(err, errlen, "Too few shares: have %d, need %d.", nblobs, k);
        return -1;
    }

    int ret = -1;
    uint8_t **ys = calloc((size_t)nblobs, sizeof(*ys));
    uint8_t *xs = malloc((size_t)nblobs);
    uint8_t *material = malloc(mlen);
    if (!ys || !xs || !material) { seterr(err, errlen, "Out of memory."); goto cleanup; }
    sodium_mlock(material, mlen);

    int got = 0;
    for (int i = 0; i < nblobs; i++) {
        share_info_t info;
        if (pqshard_inspect(blobs[i], lens[i], &info, err, errlen) != 0) goto cleanup;
        if (memcmp(info.set_id, first.set_id, SET_ID_LEN) != 0 ||
            info.k != k || info.secret_len != secret_len) {
            seterr(err, errlen, "Shares are from different splits (set mismatch).");
            goto cleanup;
        }
        for (int j = 0; j < got; j++) {
            if (xs[j] == (uint8_t)info.x) {
                seterr(err, errlen, "Duplicate share supplied (same index twice).");
                goto cleanup;
            }
        }
        ys[got] = malloc(mlen);
        if (!ys[got]) { seterr(err, errlen, "Out of memory."); goto cleanup; }
        sodium_mlock(ys[got], mlen);
        if (recover_material(blobs[i], lens[i], &info, mlen, passphrase,
                             ys[got], err, errlen) != 0) goto cleanup;
        xs[got] = (uint8_t)info.x;
        got++;
    }

    /* Use exactly k shares to interpolate. */
    if (shamir_combine(xs, ys, k, mlen, material) != 0) {
        seterr(err, errlen, "Reconstruction failed (invalid shares)."); goto cleanup;
    }

    /* Verify the embedded tag: catches wrong/foreign shares that nonetheless
     * matched the set metadata, or any silent inconsistency. */
    uint8_t tag[VERIFY_TAG_LEN];
    compute_tag(first.set_id, material, secret_len, tag);
    if (sodium_memcmp(tag, material + secret_len, VERIFY_TAG_LEN) != 0) {
        seterr(err, errlen, "Recovered secret failed verification "
                            "(inconsistent or wrong shares).");
        goto cleanup;
    }

    uint8_t *secret = malloc(secret_len);
    if (!secret) { seterr(err, errlen, "Out of memory."); goto cleanup; }
    sodium_mlock(secret, secret_len);
    memcpy(secret, material, secret_len);
    *out_secret = secret;
    *out_secret_len = secret_len;
    *out_is_text = first.is_text;
    ret = 0;

cleanup:
    if (material) { sodium_munlock(material, mlen); free(material); }
    if (ys) {
        for (int i = 0; i < nblobs; i++)
            if (ys[i]) { sodium_munlock(ys[i], mlen); free(ys[i]); }
        free(ys);
    }
    free(xs);
    return ret;
}

void pqshard_free_secret(uint8_t *secret, size_t len) {
    if (secret) { sodium_munlock(secret, len); free(secret); }
}
