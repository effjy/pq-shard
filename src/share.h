/*
 * share.h - PQ-Shard share-file format and the optional post-quantum
 * sealing layer.
 *
 * A "secret" (a master password, a disk/KEM key, or any file) is split with
 * Shamir's Secret Sharing (see shamir.c) into N share blobs, any K of which
 * reconstruct it. This module owns:
 *
 *   - the on-disk `.shard` blob layout (header + share material);
 *   - a 16-byte verification tag that is split *together with* the secret, so
 *     a successful reconstruction can be checked without the tag ever leaking
 *     anything below the threshold;
 *   - an optional sealing layer: each share's material is additionally
 *     encrypted under a passphrase via the Kyber-1024 + X448 hybrid KEM
 *     (mirroring Ciphers), so a sealed share set needs K shares *and* the
 *     passphrase.
 *
 * Requires pqshard_init() (which calls sodium_init()) first.
 */
#ifndef PQSHARD_SHARE_H
#define PQSHARD_SHARE_H

#include <stddef.h>
#include <stdint.h>

/* Argon2id strength presets (identical policy to Ciphers). */
typedef enum {
    KDF_BASIC  = 0,   /* 256 MiB              */
    KDF_MEDIUM = 1,   /* 1 GiB, parallel      */
    KDF_STRONG = 2,   /* 4 GiB, parallel      */
} kdf_level_t;

/* Hard ceiling on the secret length, so a malformed/hostile share header
 * cannot request a multi-gigabyte allocation. Generous for key material. */
#define PQSHARD_MAX_SECRET (64u * 1024u * 1024u)   /* 64 MiB */

/* Parameter limits. x-coordinates are 1..n, so n tops out at 255. */
#define PQSHARD_MIN_K 2
#define PQSHARD_MAX_N 255

/* Metadata read from a share header without reconstructing anything. */
typedef struct {
    int      version;
    int      sealed;        /* 1 if the material is passphrase-encrypted   */
    int      is_text;       /* 1 if the secret is UTF-8 text, 0 if binary  */
    int      k, n, x;       /* threshold, total, this share's x-coordinate */
    uint8_t  set_id[16];    /* identifies shares from the same split       */
    uint32_t secret_len;    /* length of the original secret in bytes      */
} share_info_t;

/* Initialise libsodium and harden the process (no core dumps / not dumpable).
 * Returns 0 on success, -1 on failure. */
int pqshard_init(void);

/* Split `secret` into `n` share blobs with threshold `k`.
 *
 * If `passphrase` is non-NULL and non-empty, every share is sealed under it
 * with the hybrid KEM at the given Argon2id `level`; otherwise plain shares
 * are produced (`level` ignored).
 *
 * On success `out_blobs[i]` receives a malloc'd buffer of `out_lens[i]` bytes
 * for i in [0, n); the caller frees each with free(). Returns 0 on success,
 * non-zero on failure with a message in err. */
int pqshard_split(const uint8_t *secret, size_t secret_len, int is_text,
                  int n, int k, const char *passphrase, kdf_level_t level,
                  uint8_t **out_blobs, size_t *out_lens,
                  char *err, size_t errlen);

/* Parse a share blob's header into `info` (no passphrase needed). Returns 0
 * on success, non-zero if the blob is not a valid share. */
int pqshard_inspect(const uint8_t *blob, size_t len, share_info_t *info,
                    char *err, size_t errlen);

/* Reconstruct the secret from `nblobs` share blobs (must be >= the threshold
 * recorded in the shares). `passphrase` is required iff the shares are sealed.
 *
 * On success a freshly malloc'd buffer holding the secret is returned through
 * `out_secret` (length `*out_secret_len`, text-ness in `*out_is_text`); free
 * it with pqshard_free_secret(). Returns 0 on success, non-zero on failure
 * (too few shares, mismatched set, wrong passphrase, corrupted/inconsistent
 * shares). */
int pqshard_combine(const uint8_t **blobs, const size_t *lens, int nblobs,
                    const char *passphrase,
                    uint8_t **out_secret, size_t *out_secret_len,
                    int *out_is_text, char *err, size_t errlen);

/* Zero and free a secret returned by pqshard_combine(). */
void pqshard_free_secret(uint8_t *secret, size_t len);

#endif /* PQSHARD_SHARE_H */
