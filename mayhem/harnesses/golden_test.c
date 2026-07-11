/*
 * keystone/mayhem/harnesses/golden_test.c — self-contained KNOWN-ANSWER test for the keystone
 * assembler. Assembles fixed asm strings across several (arch,mode) pairs and asserts the produced
 * machine-code bytes EXACTLY match keystone's documented golden encodings (from suite/test-all.sh).
 *
 * This is the PATCH-grade oracle run by mayhem/test.sh: it asserts byte-exact OUTPUT, so a no-op /
 * exit(0) patch — or any change that alters the encoder — fails. Emits "RESULT pass/fail" lines per
 * case; mayhem/test.sh parses those into a CTRF report. Exit code = number of failed cases.
 *
 * Built with NORMAL (non-sanitized) flags by build.sh and linked against libkeystone.a.
 */
#include <keystone/keystone.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0;
static int total = 0;

/* Assemble `code` for (arch,mode) and assert the encoding equals `want` (len `wantlen`). */
static void check(const char *name, ks_arch arch, int mode, int syntax,
                  const char *code, const unsigned char *want, size_t wantlen) {
    ks_engine *ks = NULL;
    unsigned char *enc = NULL;
    size_t size = 0, count = 0;
    int ok = 1;
    const char *why = "";

    total++;
    if (ks_open(arch, mode, &ks) != KS_ERR_OK) { ok = 0; why = "ks_open failed"; goto done; }
    if (syntax) ks_option(ks, KS_OPT_SYNTAX, syntax);
    if (ks_asm(ks, code, 0, &enc, &size, &count) != KS_ERR_OK) {
        ok = 0; why = "ks_asm failed"; goto done;
    }
    if (size != wantlen) { ok = 0; why = "wrong length"; goto done; }
    if (memcmp(enc, want, wantlen) != 0) { ok = 0; why = "wrong bytes"; goto done; }

done:
    if (ok) {
        printf("RESULT pass %s\n", name);
    } else {
        failures++;
        printf("RESULT fail %s (%s)", name, why);
        if (enc && size) {
            printf(" got=");
            for (size_t i = 0; i < size; i++) printf("%02x", enc[i]);
            printf(" want=");
            for (size_t i = 0; i < wantlen; i++) printf("%02x", want[i]);
        }
        printf("\n");
    }
    if (enc) ks_free(enc);
    if (ks) ks_close(ks);
}

int main(void) {
    /* x86-32 Intel: add eax, ecx -> 01 c8 */
    check("x86_32_add", KS_ARCH_X86, KS_MODE_32, KS_OPT_SYNTAX_INTEL,
          "add eax, ecx", (const unsigned char[]){0x01,0xc8}, 2);
    /* x86-64 Intel: add rax, rcx -> 48 01 c8 */
    check("x86_64_add", KS_ARCH_X86, KS_MODE_64, KS_OPT_SYNTAX_INTEL,
          "add rax, rcx", (const unsigned char[]){0x48,0x01,0xc8}, 3);
    /* x86-32 ATT: add %ecx, %eax -> 01 c8 */
    check("x86_32att_add", KS_ARCH_X86, KS_MODE_32, KS_OPT_SYNTAX_ATT,
          "add %ecx, %eax", (const unsigned char[]){0x01,0xc8}, 2);
    /* ARM LE: sub r1, r2, r5 -> 05 10 42 e0 */
    check("arm_sub", KS_ARCH_ARM, KS_MODE_ARM+KS_MODE_LITTLE_ENDIAN, 0,
          "sub r1, r2, r5", (const unsigned char[]){0x05,0x10,0x42,0xe0}, 4);
    /* Thumb LE: movs r4, #0xf0 -> f0 24 */
    check("thumb_movs", KS_ARCH_ARM, KS_MODE_THUMB+KS_MODE_LITTLE_ENDIAN, 0,
          "movs r4, #0xf0", (const unsigned char[]){0xf0,0x24}, 2);
    /* Thumb BE: movs r4, #0xf0 -> 24 f0 */
    check("thumbbe_movs", KS_ARCH_ARM, KS_MODE_THUMB+KS_MODE_BIG_ENDIAN, 0,
          "movs r4, #0xf0", (const unsigned char[]){0x24,0xf0}, 2);
    /* SPARC BE: add %g1, %g2, %g3 -> 86 00 40 02 */
    check("sparcbe_add", KS_ARCH_SPARC, KS_MODE_SPARC32+KS_MODE_BIG_ENDIAN, 0,
          "add %g1, %g2, %g3", (const unsigned char[]){0x86,0x00,0x40,0x02}, 4);
    /* SPARC LE: add %g1, %g2, %g3 -> 02 40 00 86 */
    check("sparc_add", KS_ARCH_SPARC, KS_MODE_SPARC32+KS_MODE_LITTLE_ENDIAN, 0,
          "add %g1, %g2, %g3", (const unsigned char[]){0x02,0x40,0x00,0x86}, 4);
    /* MIPS BE: and $9, $6, $7 -> 00 c7 48 24 */
    check("mipsbe_and", KS_ARCH_MIPS, KS_MODE_MIPS32+KS_MODE_BIG_ENDIAN, 0,
          "and $9, $6, $7", (const unsigned char[]){0x00,0xc7,0x48,0x24}, 4);
    /* MIPS LE: and $9, $6, $7 -> 24 48 c7 00 */
    check("mips_and", KS_ARCH_MIPS, KS_MODE_MIPS32+KS_MODE_LITTLE_ENDIAN, 0,
          "and $9, $6, $7", (const unsigned char[]){0x24,0x48,0xc7,0x00}, 4);
    /* PPC32 BE: add 1, 2, 3 -> 7c 22 1a 14 */
    check("ppc32be_add", KS_ARCH_PPC, KS_MODE_PPC32+KS_MODE_BIG_ENDIAN, 0,
          "add 1, 2, 3", (const unsigned char[]){0x7c,0x22,0x1a,0x14}, 4);
    /* PPC64 BE: add 1, 2, 3 -> 7c 22 1a 14 */
    check("ppc64be_add", KS_ARCH_PPC, KS_MODE_PPC64+KS_MODE_BIG_ENDIAN, 0,
          "add 1, 2, 3", (const unsigned char[]){0x7c,0x22,0x1a,0x14}, 4);

    /* Negative case: invalid mnemonic must FAIL to assemble (assembler rejects garbage). */
    {
        ks_engine *ks = NULL; unsigned char *enc = NULL; size_t size = 0, count = 0;
        total++;
        if (ks_open(KS_ARCH_X86, KS_MODE_64, &ks) == KS_ERR_OK) {
            int rc = ks_asm(ks, "this_is_not_an_instruction qq", 0, &enc, &size, &count);
            if (rc == KS_ERR_OK) { failures++; printf("RESULT fail x86_64_reject_garbage (assembled invalid asm)\n"); }
            else { printf("RESULT pass x86_64_reject_garbage\n"); }
            if (enc) ks_free(enc);
            ks_close(ks);
        } else { failures++; printf("RESULT fail x86_64_reject_garbage (ks_open failed)\n"); }
    }

    printf("SUMMARY total=%d passed=%d failed=%d\n", total, total - failures, failures);
    return failures;
}
