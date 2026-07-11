# keystone: `AsmParser::Run()` never terminates on a rejected token

**Reproducer:** `input` — `6e 6f 70 0a ff ff ff ff ff ff ff ff 01`
(`nop`, newline, eight `0xff` bytes; the trailing `01` is the harness's syntax selector byte, which
the harness overwrites with the string terminator).

**Reproduce (against an UNBOUNDED build — see "Why it does not reproduce here" below):**

```
/mayhem/x86_64-standalone mayhem/x86_64/known-findings/asmparser-run-infinite-loop/input
```

**What happens.** `ks_asm()` never returns. `llvm/lib/MC/MCParser/AsmParser.cpp`:

```c++
  while (Lexer.isNot(AsmToken::Eof)) {
    ParseStatementInfo Info;
    if (!parseStatement(Info, nullptr, Address)) { count++; continue; }
    if (!KsError) { KsError = Info.KsError; return 0; }
    // We had an error, validate that one was emitted and recover by skipping to the next line.
    //eatToEndOfStatement();          <-- recovery COMMENTED OUT upstream
  }
```

On the fall-through error path the lexer is never advanced, so the loop re-lexes the same rejected
token forever. Backtrace while spinning (`AsmParser.cpp:1449` inside `AsmParser.cpp:712`):

```
#1  AsmParser::parseStatement (...)  at llvm/lib/MC/MCParser/AsmParser.cpp:1449
#2  AsmParser::Run (...)             at llvm/lib/MC/MCParser/AsmParser.cpp:712
#3  ks_asm (...)                     at llvm/keystone/ks.cpp:691
```

Resident memory is flat while it spins — a pure non-allocating loop, not an expansion blowup. It is
architecture independent: the loop lives in the generic parser that every `KS_ARCH_*` shares.

**Why it matters.** libFuzzer reaches this input from the committed seed corpus in roughly 50
executions, so before it was bounded every Mayhem campaign stalled on it within seconds of starting.

**Why it does not reproduce in the shipped image.** `mayhem/build.sh` builds the FUZZ library from a
shadow copy of `AsmParser.cpp` (`mayhem/shadow-patch-asmparser.py`) that adds a no-progress guard, so
this input now returns an ordinary `ks_asm()` error instead of hanging. The upstream source file is
unmodified, and the golden-test library that `mayhem/test.sh` runs is built from it as-is — so this
directory is the record of the underlying upstream defect.

Kept here, and deliberately NOT in `mayhem/x86_64/testsuite/`: Mayhem replays the whole seed corpus
on every run, so a non-terminating seed would fail every future run permanently.
