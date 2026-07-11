#!/usr/bin/env python3
"""
shadow-patch-asmparser.py — build-time SHADOW COPY of llvm/lib/MC/MCParser/AsmParser.cpp for the
FUZZ build only.

WHY
---
Two distinct classes of "ks_asm() never comes back" live in this file, and both stall a Mayhem
campaign within seconds of it starting.

1. A genuine upstream INFINITE LOOP in AsmParser::Run():

       while (Lexer.isNot(AsmToken::Eof)) {
         ParseStatementInfo Info;
         if (!parseStatement(Info, nullptr, Address)) { count++; continue; }
         if (!KsError) { KsError = Info.KsError; return 0; }
         ...
         //eatToEndOfStatement();      <-- keystone COMMENTED OUT the error recovery
       }

   On that fall-through error path the lexer is never advanced, so Run() spins forever. Minimal
   reproducer: b"nop\\n\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff" (a valid statement followed by a
   line of bytes the lexer rejects without consuming). Reached from the shipped seed corpus in
   roughly 50 libFuzzer executions, on every architecture, because the loop lives in the shared
   generic parser. Fixed here with a no-progress guard plus a hard iteration ceiling.

2. ABSURD REPEAT COUNTS on three directives that materialise their output eagerly: `.rept`/`.rep`
   (macro body expanded Count times into a buffer), `.fill` (NumValues values emitted one at a
   time) and `.space`/`.skip` and `.zero` (NumBytes emitted). `.rept 100000000` and
   `.fill 1000000000, 1, 0` do not return inside 400s; `.zero 1000000000` takes ~20s and ~1GB.
   That is not a bug — an assembler asked to repeat something a hundred million times is supposed
   to do the work — but it is a multi-minute non-finding that starves the campaign, so the fuzz
   build rejects counts far beyond anything a 4KB input could legitimately want.

HOW (additive)
--------------
This writes a PATCHED COPY to a scratch path. mayhem/build.sh compiles that copy with the exact
flags CMake used for the original (read out of the build's compile_commands.json) and substitutes
the object into libkeystone.a with `ar r`, for the FUZZ library only. The committed upstream file is
never touched, so the integration commit stays purely additive, and the golden-test library that
mayhem/test.sh exercises is built from PRISTINE sources so the oracle keeps testing real keystone.

Usage: shadow-patch-asmparser.py <src AsmParser.cpp> <dst AsmParser.cpp>
Exit:  0 patched, 1 an anchor no longer matches exactly once (upstream moved), 2 usage.
"""
import sys

# libFuzzer's default -max_len is 4096, so even an input that is nothing but statement separators
# yields ~4k statements. 200k iterations is ~50x that and still returns in well under a second.
MAX_ITERS = 200000
# Repetition ceiling for the eagerly-materialising directives. 1M repeats/bytes is orders of
# magnitude more than any real assembly source in a 4KB fuzz input and completes in ~0.1s.
MAX_REPEAT = 1000000

PATCHES = [
    # --- AsmParser::Run(): no-progress guard + iteration ceiling -------------------------------
    ("""  // While we have input, parse each statement.
  while (Lexer.isNot(AsmToken::Eof)) {
    ParseStatementInfo Info;
""",
     """  // While we have input, parse each statement.
  // KEYSTONE-FUZZ (mayhem/shadow-patch-asmparser.py): bound this loop.
  const char *KsFuzzPrevLoc = nullptr;
  unsigned long KsFuzzIters = 0;
  while (Lexer.isNot(AsmToken::Eof)) {
    if (++KsFuzzIters > %(MAX_ITERS)dUL) {
      // Far beyond any legitimate statement count: report an ordinary parse error.
      KsError = KS_ERR_ASM_DIRECTIVE_TOKEN;
      return count;
    }
    ParseStatementInfo Info;
"""),
    ("""    //eatToEndOfStatement();
  }
""",
     """    //eatToEndOfStatement();
    // KEYSTONE-FUZZ (mayhem/shadow-patch-asmparser.py): the recovery call above is commented out
    // upstream, so this error path does not advance the lexer and the loop spins forever. If the
    // lexer sits exactly where it did on the previous error iteration no progress is possible:
    // return with the error already recorded in KsError instead of hanging.
    {
      const char *KsFuzzLoc = Lexer.getLoc().getPointer();
      if (KsFuzzLoc == KsFuzzPrevLoc)
        return count;
      KsFuzzPrevLoc = KsFuzzLoc;
    }
  }
"""),
    # --- .rept / .rep : cap the repeat count ----------------------------------------------------
    ("""  if (Count < 0) {
    //return Error(CountLoc, "Count is negative");
    KsError = KS_ERR_ASM_DIRECTIVE_INVALID;
    return true;
  }
""",
     """  if (Count < 0) {
    //return Error(CountLoc, "Count is negative");
    KsError = KS_ERR_ASM_DIRECTIVE_INVALID;
    return true;
  }

  // KEYSTONE-FUZZ (mayhem/shadow-patch-asmparser.py): the body below is expanded Count times into
  // a buffer, so an absurd count is minutes of work and gigabytes of memory for no finding.
  if (Count > %(MAX_REPEAT)dLL) {
    KsError = KS_ERR_ASM_DIRECTIVE_INVALID;
    return true;
  }
"""),
    # --- .fill : cap the value count ------------------------------------------------------------
    ("""  if (NumValues > 0) {
    int64_t NonZeroFillSize = FillSize > 4 ? 4 : FillSize;
""",
     """  // KEYSTONE-FUZZ (mayhem/shadow-patch-asmparser.py): each value is emitted individually below.
  if (NumValues > %(MAX_REPEAT)dLL) {
    KsError = KS_ERR_ASM_DIRECTIVE_INVALID;
    return true;
  }

  if (NumValues > 0) {
    int64_t NonZeroFillSize = FillSize > 4 ? 4 : FillSize;
"""),
    # --- .zero : cap the byte count -------------------------------------------------------------
    ("""  getStreamer().EmitFill(NumBytes, Val);
""",
     """  // KEYSTONE-FUZZ (mayhem/shadow-patch-asmparser.py): NumBytes bytes are materialised below.
  if (NumBytes > %(MAX_REPEAT)dLL) {
    KsError = KS_ERR_ASM_DIRECTIVE_INVALID;
    return true;
  }

  getStreamer().EmitFill(NumBytes, Val);
"""),
    # --- .space / .skip : cap the byte count ----------------------------------------------------
    ("""  // FIXME: Sometimes the fill expr is 'nop' if it isn't supplied, instead of 0.
  getStreamer().EmitFill(NumBytes, FillExpr);
""",
     """  // KEYSTONE-FUZZ (mayhem/shadow-patch-asmparser.py): NumBytes bytes are materialised below.
  if (NumBytes > %(MAX_REPEAT)dLL) {
    KsError = KS_ERR_ASM_DIRECTIVE_INVALID;
    return true;
  }

  // FIXME: Sometimes the fill expr is 'nop' if it isn't supplied, instead of 0.
  getStreamer().EmitFill(NumBytes, FillExpr);
"""),
]


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: shadow-patch-asmparser.py <src AsmParser.cpp> <dst AsmParser.cpp>",
              file=sys.stderr)
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    text = open(src, encoding="utf-8", errors="surrogateescape").read()
    subst = {"MAX_ITERS": MAX_ITERS, "MAX_REPEAT": MAX_REPEAT}

    for i, (anchor, repl) in enumerate(PATCHES, 1):
        n = text.count(anchor)
        if n != 1:
            print(f"shadow-patch-asmparser: anchor #{i} matched {n} times (want exactly 1) in "
                  f"{src} — upstream moved; update this script", file=sys.stderr)
            return 1
        text = text.replace(anchor, repl % subst)

    with open(dst, "w", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write(text)
    print(f"shadow-patch-asmparser: wrote bounded copy of {src} -> {dst} "
          f"(max_iters={MAX_ITERS}, max_repeat={MAX_REPEAT})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
