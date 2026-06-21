/*
 * shamir.c - Shamir's Secret Sharing over GF(2^8). See shamir.h.
 *
 * GF(2^8) uses the AES reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
 * Multiplication goes through log/antilog tables built once at first use over
 * the generator 0x03; this keeps the inner interpolation loop to table
 * look-ups rather than carry-less multiplies.
 *
 * Secrecy depends entirely on the higher coefficients being uniformly random,
 * so they are drawn with libsodium's randombytes_buf and the working buffers
 * are pinned and wiped.
 */
#include "shamir.h"

#include <string.h>
#include <sodium.h>

/* ----- GF(2^8) arithmetic ---------------------------------------------- */

static uint8_t gf_log[256];
static uint8_t gf_exp[512];   /* doubled so exp[a+b] needs no mod 255 */
static int     gf_ready = 0;

static void gf_init(void) {
    if (gf_ready) return;
    uint8_t x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = x;
        gf_log[x] = (uint8_t)i;
        /* multiply x by the generator 0x03 = (x+1): (x<<1) ^ x, with the
         * conditional reduction by 0x11b when bit 7 overflows. */
        uint8_t hi = x & 0x80;
        x = (uint8_t)(x << 1);
        if (hi) x ^= 0x1b;
        x ^= gf_exp[i];          /* + original value -> multiply by 3 */
    }
    /* gf_exp wraps with period 255; mirror it into the upper half so a sum of
     * two logs (each <= 254) can index directly without a modulo. */
    for (int i = 255; i < 512; i++) gf_exp[i] = gf_exp[i - 255];
    gf_log[0] = 0;               /* unused; log(0) is undefined */
    gf_ready = 1;
}

static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    return gf_exp[gf_log[a] + gf_log[b]];
}

/* a / b in GF(2^8); b must be non-zero. */
static inline uint8_t gf_div(uint8_t a, uint8_t b) {
    if (a == 0) return 0;
    /* log(a) - log(b) mod 255, kept non-negative by adding 255. */
    return gf_exp[gf_log[a] + 255 - gf_log[b]];
}

/* Evaluate the polynomial with coefficients coef[0..degree] (coef[0] is the
 * constant term, i.e. the secret byte) at point x, using Horner's method. */
static uint8_t gf_eval(const uint8_t *coef, int degree, uint8_t x) {
    uint8_t y = coef[degree];
    for (int i = degree - 1; i >= 0; i--)
        y = (uint8_t)(gf_mul(y, x) ^ coef[i]);
    return y;
}

/* ----- Public API ------------------------------------------------------- */

int shamir_split(const uint8_t *secret, size_t len, int n, int k,
                 uint8_t *xs, uint8_t **ys) {
    if (k < 2 || n < k || n > 255 || len == 0) return -1;
    gf_init();

    /* x-coordinates 1..n (never 0, where the secret lives). */
    for (int i = 0; i < n; i++) xs[i] = (uint8_t)(i + 1);

    /* coef[0] = secret byte; coef[1..k-1] = fresh random per byte. */
    uint8_t coef[256];
    sodium_mlock(coef, sizeof(coef));
    for (size_t b = 0; b < len; b++) {
        coef[0] = secret[b];
        randombytes_buf(coef + 1, (size_t)(k - 1));
        for (int i = 0; i < n; i++)
            ys[i][b] = gf_eval(coef, k - 1, xs[i]);
    }
    sodium_munlock(coef, sizeof(coef));   /* zeroes the coefficients */
    return 0;
}

int shamir_combine(const uint8_t *xs, uint8_t * const *ys, int k, size_t len,
                   uint8_t *out) {
    if (k < 2 || len == 0) return -1;
    gf_init();

    /* All x-coordinates must be distinct and non-zero, else the Lagrange
     * basis denominators vanish or collide. */
    for (int i = 0; i < k; i++) {
        if (xs[i] == 0) return -1;
        for (int j = i + 1; j < k; j++)
            if (xs[i] == xs[j]) return -1;
    }

    /* Precompute each share's Lagrange basis weight at x = 0:
     *   w_i = prod_{j!=i} x_j / (x_i ^ x_j)
     * (subtraction is XOR in GF(2^8)). The secret byte is sum_i w_i * y_i. */
    uint8_t w[255];
    for (int i = 0; i < k; i++) {
        uint8_t num = 1, den = 1;
        for (int j = 0; j < k; j++) {
            if (j == i) continue;
            num = gf_mul(num, xs[j]);
            den = gf_mul(den, (uint8_t)(xs[i] ^ xs[j]));
        }
        w[i] = gf_div(num, den);
    }

    for (size_t b = 0; b < len; b++) {
        uint8_t acc = 0;
        for (int i = 0; i < k; i++)
            acc ^= gf_mul(w[i], ys[i][b]);
        out[b] = acc;
    }
    return 0;
}
