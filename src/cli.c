/*
 * cli.c - PQ-Shard command-line interface.
 *
 *   pqshard split   [options]            split a secret into shares
 *   pqshard combine  share files...      reconstruct a secret from shares
 *
 * The CLI is a thin shell over share.c; it owns argument parsing, file I/O,
 * and reading a passphrase from the terminal with echo disabled.
 */
#include "share.h"

#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>

#ifndef PQSHARD_VERSION
#define PQSHARD_VERSION "1.0.2"
#endif

#define MAX_PASS 4096

static void usage(FILE *f) {
    fprintf(f,
"PQ-Shard v" PQSHARD_VERSION " - post-quantum Shamir secret sharing.\n"
"\n"
"Usage:\n"
"  pqshard split   [options]                Split a secret into N shares.\n"
"  pqshard combine [options] <share>...     Reconstruct a secret from shares.\n"
"  pqshard inspect <share>...               Show share metadata (no secret).\n"
"\n"
"split options:\n"
"  -n N            Total number of shares to create   (default 5)\n"
"  -k K            Threshold needed to reconstruct    (default 3)\n"
"  -f FILE         Read the secret from FILE (binary). Default: read stdin.\n"
"  -t TEXT         Use TEXT as the secret (a passphrase/key string).\n"
"  -o DIR          Directory to write share files into (default '.').\n"
"  -p PREFIX       Share file name prefix              (default 'secret').\n"
"  -s, --seal      Additionally seal each share under a passphrase using the\n"
"                  Kyber-1024 + X448 hybrid KEM (prompted). Then K shares AND\n"
"                  the passphrase are required to reconstruct.\n"
"      --kdf LVL   KDF strength with --seal: basic|medium|strong (default medium).\n"
"\n"
"combine options:\n"
"  -o FILE         Write the recovered secret to FILE. Default: stdout.\n"
"      --seal      The shares are sealed; prompt for the passphrase.\n"
"                  (Auto-detected from the shares too.)\n"
"\n"
"Examples:\n"
"  printf 'my master key' | pqshard split -n 5 -k 3 -o ./shares\n"
"  pqshard split -f disk.key -n 3 -k 2 -s -o ./shares\n"
"  pqshard combine ./shares/secret.1of5.shard ./shares/secret.3of5.shard \\\n"
"                  ./shares/secret.5of5.shard -o recovered.key\n");
}

/* Read a passphrase from the terminal with echo off. Returns 0 on success. */
static int read_passphrase(const char *prompt, char *buf, size_t buflen) {
    struct termios old, raw;
    FILE *tty = fopen("/dev/tty", "r+");
    if (!tty) tty = stdin;
    int have_term = (tcgetattr(fileno(tty), &old) == 0);
    if (have_term) {
        raw = old;
        raw.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(fileno(tty), TCSAFLUSH, &raw);
    }
    fputs(prompt, stderr); fflush(stderr);
    char *r = fgets(buf, (int)buflen, tty);
    if (have_term) {
        tcsetattr(fileno(tty), TCSAFLUSH, &old);
        fputs("\n", stderr);
    }
    if (tty != stdin) fclose(tty);
    if (!r) return -1;
    size_t L = strlen(buf);
    if (L && buf[L - 1] == '\n') buf[--L] = '\0';
    return 0;
}

/* Read an entire stream into a malloc'd buffer. Returns 0 on success. */
static int read_all(FILE *f, uint8_t **out, size_t *outlen) {
    size_t cap = 65536, len = 0;
    uint8_t *buf = malloc(cap);
    if (!buf) return -1;
    for (;;) {
        if (len == cap) {
            if (cap > PQSHARD_MAX_SECRET) { free(buf); return -2; }
            cap *= 2;
            uint8_t *nb = realloc(buf, cap);
            if (!nb) { free(buf); return -1; }
            buf = nb;
        }
        size_t r = fread(buf + len, 1, cap - len, f);
        len += r;
        if (r == 0) {
            if (feof(f)) break;
            free(buf); return -1;
        }
    }
    *out = buf; *outlen = len;
    return 0;
}

static int read_file(const char *path, uint8_t **out, size_t *outlen) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    int rc = read_all(f, out, outlen);
    fclose(f);
    return rc;
}

static int kdf_from_string(const char *s, kdf_level_t *out) {
    if (!strcmp(s, "basic"))  { *out = KDF_BASIC;  return 0; }
    if (!strcmp(s, "medium")) { *out = KDF_MEDIUM; return 0; }
    if (!strcmp(s, "strong")) { *out = KDF_STRONG; return 0; }
    return -1;
}

/* ----- split ------------------------------------------------------------ */

static int cmd_split(int argc, char **argv) {
    int n = 5, k = 3, seal = 0;
    const char *infile = NULL, *text = NULL, *outdir = ".", *prefix = "secret";
    kdf_level_t level = KDF_MEDIUM;

    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-n") && i + 1 < argc) n = atoi(argv[++i]);
        else if (!strcmp(a, "-k") && i + 1 < argc) k = atoi(argv[++i]);
        else if (!strcmp(a, "-f") && i + 1 < argc) infile = argv[++i];
        else if (!strcmp(a, "-t") && i + 1 < argc) text = argv[++i];
        else if (!strcmp(a, "-o") && i + 1 < argc) outdir = argv[++i];
        else if (!strcmp(a, "-p") && i + 1 < argc) prefix = argv[++i];
        else if (!strcmp(a, "-s") || !strcmp(a, "--seal")) seal = 1;
        else if (!strcmp(a, "--kdf") && i + 1 < argc) {
            if (kdf_from_string(argv[++i], &level) != 0) {
                fprintf(stderr, "pqshard: unknown --kdf value '%s'.\n", argv[i]);
                return 1;
            }
        } else {
            fprintf(stderr, "pqshard split: unexpected argument '%s'.\n", a);
            return 1;
        }
    }
    if (n < k || k < 2 || n > 255) {
        fprintf(stderr, "pqshard: need 2 <= threshold (-k) <= shares (-n) <= 255.\n");
        return 1;
    }

    /* Gather the secret. */
    uint8_t *secret = NULL; size_t secret_len = 0; int is_text = 0;
    if (text) {
        secret_len = strlen(text);
        secret = malloc(secret_len ? secret_len : 1);
        if (!secret) { fprintf(stderr, "pqshard: out of memory.\n"); return 1; }
        memcpy(secret, text, secret_len);
        is_text = 1;
    } else if (infile) {
        int rc = read_file(infile, &secret, &secret_len);
        if (rc != 0) {
            fprintf(stderr, "pqshard: cannot read '%s': %s\n", infile,
                    rc == -2 ? "file too large" : strerror(errno));
            return 1;
        }
    } else {
        int rc = read_all(stdin, &secret, &secret_len);
        if (rc != 0) { fprintf(stderr, "pqshard: error reading stdin.\n"); return 1; }
        /* A piped passphrase typically has no trailing newline intent; if the
         * only trailing byte is a newline, drop it so `echo x | split` is sane. */
        if (secret_len && secret[secret_len - 1] == '\n') secret_len--;
        is_text = 1;
    }
    if (secret_len == 0) {
        fprintf(stderr, "pqshard: the secret is empty.\n");
        free(secret); return 1;
    }

    char pass[MAX_PASS] = {0};
    if (seal) {
        char pass2[MAX_PASS] = {0};
        if (read_passphrase("Sealing passphrase: ", pass, sizeof pass) != 0 ||
            read_passphrase("Confirm passphrase: ", pass2, sizeof pass2) != 0) {
            fprintf(stderr, "pqshard: could not read passphrase.\n");
            sodium_memzero(pass, sizeof pass); sodium_memzero(pass2, sizeof pass2);
            free(secret); return 1;
        }
        if (strcmp(pass, pass2) != 0) {
            fprintf(stderr, "pqshard: passphrases do not match.\n");
            sodium_memzero(pass, sizeof pass); sodium_memzero(pass2, sizeof pass2);
            free(secret); return 1;
        }
        sodium_memzero(pass2, sizeof pass2);
        if (!*pass) {
            fprintf(stderr, "pqshard: empty passphrase; not sealing.\n");
            free(secret); return 1;
        }
    }

    uint8_t **blobs = calloc((size_t)n, sizeof(*blobs));
    size_t *lens = calloc((size_t)n, sizeof(*lens));
    if (!blobs || !lens) { fprintf(stderr, "pqshard: out of memory.\n"); free(secret); return 1; }

    char err[256] = {0};
    int rc = pqshard_split(secret, secret_len, is_text, n, k,
                           seal ? pass : NULL, level, blobs, lens, err, sizeof err);
    sodium_memzero(pass, sizeof pass);
    sodium_memzero(secret, secret_len);
    free(secret);
    if (rc != 0) {
        fprintf(stderr, "pqshard: %s\n", err);
        free(blobs); free(lens);
        return 1;
    }

    /* Write each share file: <outdir>/<prefix>.<x>of<n>.shard */
    int failed = 0;
    for (int i = 0; i < n; i++) {
        char path[4096];
        if (snprintf(path, sizeof path, "%s/%s.%dof%d.shard",
                     outdir, prefix, i + 1, n) >= (int)sizeof path) {
            fprintf(stderr, "pqshard: output path too long.\n"); failed = 1; break;
        }
        FILE *f = fopen(path, "wb");
        if (!f || fwrite(blobs[i], 1, lens[i], f) != lens[i]) {
            fprintf(stderr, "pqshard: cannot write '%s': %s\n", path, strerror(errno));
            if (f) fclose(f);
            failed = 1; break;
        }
        fclose(f);
        printf("  %s\n", path);
    }

    for (int i = 0; i < n; i++) free(blobs[i]);
    free(blobs); free(lens);

    if (failed) return 1;
    printf("\nSplit into %d shares; any %d reconstruct the secret%s.\n",
           n, k, seal ? " (passphrase also required)" : "");
    return 0;
}

/* ----- combine ---------------------------------------------------------- */

static int cmd_combine(int argc, char **argv) {
    const char *outfile = NULL;
    int want_seal = 0;
    const char *paths[256]; int npaths = 0;

    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-o") && i + 1 < argc) outfile = argv[++i];
        else if (!strcmp(a, "--seal") || !strcmp(a, "-s")) want_seal = 1;
        else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "pqshard combine: unknown option '%s'.\n", a);
            return 1;
        } else {
            if (npaths >= (int)(sizeof paths / sizeof paths[0])) {
                fprintf(stderr, "pqshard: too many share files.\n"); return 1;
            }
            paths[npaths++] = a;
        }
    }
    if (npaths < 2) {
        fprintf(stderr, "pqshard: supply at least two share files.\n");
        return 1;
    }

    /* Load every share file. */
    const uint8_t **blobs = calloc((size_t)npaths, sizeof(*blobs));
    size_t *lens = calloc((size_t)npaths, sizeof(*lens));
    if (!blobs || !lens) { fprintf(stderr, "pqshard: out of memory.\n"); return 1; }

    int sealed = 0;
    for (int i = 0; i < npaths; i++) {
        uint8_t *b = NULL; size_t L = 0;
        if (read_file(paths[i], &b, &L) != 0) {
            fprintf(stderr, "pqshard: cannot read '%s': %s\n", paths[i], strerror(errno));
            goto fail;
        }
        blobs[i] = b; lens[i] = L;
        share_info_t info; char e[256];
        if (pqshard_inspect(b, L, &info, e, sizeof e) == 0 && info.sealed) sealed = 1;
    }

    char pass[MAX_PASS] = {0};
    if (sealed || want_seal) {
        if (read_passphrase("Passphrase: ", pass, sizeof pass) != 0) {
            fprintf(stderr, "pqshard: could not read passphrase.\n");
            goto fail;
        }
    }

    uint8_t *secret = NULL; size_t secret_len = 0; int is_text = 0;
    char err[256] = {0};
    int rc = pqshard_combine(blobs, lens, npaths, *pass ? pass : NULL,
                             &secret, &secret_len, &is_text, err, sizeof err);
    sodium_memzero(pass, sizeof pass);
    for (int i = 0; i < npaths; i++) free((void *)blobs[i]);
    free(blobs); free(lens);
    if (rc != 0) {
        fprintf(stderr, "pqshard: %s\n", err);
        return 1;
    }

    if (outfile) {
        FILE *f = fopen(outfile, "wb");
        if (!f || fwrite(secret, 1, secret_len, f) != secret_len) {
            fprintf(stderr, "pqshard: cannot write '%s': %s\n", outfile, strerror(errno));
            if (f) fclose(f);
            pqshard_free_secret(secret, secret_len);
            return 1;
        }
        fclose(f);
        fprintf(stderr, "Recovered %zu-byte secret -> %s\n", secret_len, outfile);
    } else {
        fwrite(secret, 1, secret_len, stdout);
        if (is_text) fputc('\n', stderr);
    }
    pqshard_free_secret(secret, secret_len);
    return 0;

fail:
    for (int i = 0; i < npaths; i++) free((void *)blobs[i]);
    free(blobs); free(lens);
    return 1;
}

/* ----- inspect ---------------------------------------------------------- */

static int cmd_inspect(int argc, char **argv) {
    if (argc < 1) { fprintf(stderr, "pqshard: supply share file(s).\n"); return 1; }
    int rc = 0;
    for (int i = 0; i < argc; i++) {
        uint8_t *b = NULL; size_t L = 0;
        if (read_file(argv[i], &b, &L) != 0) {
            fprintf(stderr, "pqshard: cannot read '%s'.\n", argv[i]); rc = 1; continue;
        }
        share_info_t info; char err[256];
        if (pqshard_inspect(b, L, &info, err, sizeof err) != 0) {
            fprintf(stderr, "%s: %s\n", argv[i], err); rc = 1; free(b); continue;
        }
        char setid_hex[2 * 16 + 1];
        sodium_bin2hex(setid_hex, sizeof setid_hex, info.set_id, 16);
        printf("%s:\n", argv[i]);
        printf("  share %d of %d   threshold %d   set %s\n",
               info.x, info.n, info.k, setid_hex);
        printf("  secret %u bytes   %s   %s\n", info.secret_len,
               info.is_text ? "text" : "binary",
               info.sealed ? "SEALED (passphrase required)" : "plain");
        free(b);
    }
    return rc;
}

int main(int argc, char **argv) {
    if (pqshard_init() != 0) {
        fprintf(stderr, "pqshard: failed to initialise crypto library.\n");
        return 1;
    }
    if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        usage(argc < 2 ? stderr : stdout);
        return argc < 2 ? 1 : 0;
    }
    if (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version")) {
        printf("PQ-Shard v%s\n", PQSHARD_VERSION);
        return 0;
    }
    if (!strcmp(argv[1], "split"))   return cmd_split(argc - 2, argv + 2);
    if (!strcmp(argv[1], "combine")) return cmd_combine(argc - 2, argv + 2);
    if (!strcmp(argv[1], "inspect")) return cmd_inspect(argc - 2, argv + 2);

    fprintf(stderr, "pqshard: unknown command '%s'.\n\n", argv[1]);
    usage(stderr);
    return 1;
}
