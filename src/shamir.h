/*
 * shamir.h - Shamir's Secret Sharing over GF(2^8).
 *
 * Splits a secret of arbitrary length into N shares such that any K of them
 * reconstruct it and any K-1 reveal nothing (information-theoretic secrecy).
 * Each byte of the secret is the constant term of an independent random
 * degree-(K-1) polynomial over GF(2^8); a share is that polynomial family
 * evaluated at a distinct non-zero x-coordinate.
 *
 * This module is pure arithmetic: it knows nothing about files, passwords or
 * the post-quantum sealing layer. Randomness comes from libsodium, so
 * sodium_init() must have been called first.
 */
#ifndef PQSHARD_SHAMIR_H
#define PQSHARD_SHAMIR_H

#include <stddef.h>
#include <stdint.h>

/* A reconstructed/serialised share's y-material has the same length as the
 * secret that was split. The x-coordinate is carried separately (1 byte). */

/* Split `secret` (len bytes) into `n` shares with threshold `k`.
 *
 * On success the caller-provided arrays are filled:
 *   xs[i]   = the i-th share's x-coordinate (distinct, in 1..255)
 *   ys[i]   = a buffer of `len` bytes receiving the i-th share's y-material
 *             (caller allocates each ys[i] with at least `len` bytes)
 *
 * Requires 2 <= k <= n <= 255 and len >= 1. Returns 0 on success, -1 on
 * invalid parameters. The x-coordinates are 1,2,...,n.
 */
int shamir_split(const uint8_t *secret, size_t len, int n, int k,
                 uint8_t *xs, uint8_t **ys);

/* Reconstruct the secret from `k` shares via Lagrange interpolation at x=0.
 *
 *   xs[i]   = the i-th supplied share's x-coordinate (must be distinct, non-zero)
 *   ys[i]   = that share's y-material (`len` bytes)
 *   out     = buffer of `len` bytes receiving the recovered secret
 *
 * Returns 0 on success, -1 on invalid parameters (k < 2, duplicate/zero x).
 * Note: SSS itself cannot tell "correct" from "wrong" shares; callers verify
 * the result against a commitment (see share.c).
 */
int shamir_combine(const uint8_t *xs, uint8_t * const *ys, int k, size_t len,
                   uint8_t *out);

#endif /* PQSHARD_SHAMIR_H */
