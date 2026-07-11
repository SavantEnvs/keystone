// mayhem/lsan_off.cc — turn LeakSanitizer OFF at BUILD time (SPEC §6.2 item 15).
//
// `-fsanitize=address` always bundles LeakSanitizer in and there is no flag that keeps ASan while
// dropping only leak detection, so the sanctioned way to drop it is this one-symbol translation
// unit, compiled with $SANITIZER_FLAGS and linked into every fuzz binary AND every -standalone
// reproducer. ASan's memory-corruption checks and UBSan stay fully active and halting; only leak
// reporting is affected.
//
// It matters here: keystone's own error paths leak (e.g. ks_open()'s ARM mode switch returns
// KS_ERR_MODE without deleting the freshly-allocated ks_struct), and LLVM's MC layer leaks on the
// ks_asm() failure paths the fuzzer spends almost all of its time in. Leaks are not the bug class
// this fleet fuzzes for, and leak reports on "this is not valid asm" input would drown the real
// memory-safety findings.
//
// Build-time only, by design: the runtime enable/disable API is unreliable and the ASan/LSan
// runtime option set belongs to Mayhem, not to the target.
extern "C" int __lsan_is_turned_off(void) { return 1; }
