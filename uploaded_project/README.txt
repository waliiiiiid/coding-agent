CSE451 - Assignment 1: DES (ECB) - C and Verilog Bonus
======================================================

FILES
  2200405.c                   REQUIRED submission; corrected and tested.
  des_core.v                  BONUS Verilog DES core; original file is unchanged.
  tb_des_core.v               BONUS testbench; corrected failure/timeout handling.
  DES Implementation Report.pdf  Updated technical report and verification notes.

TEAM: 2200405, 2200820, 2201048, 2200243, 2200725

SUBMISSION RULE
  The written assignment requires one C source file. Submit 2200405.c
  for the standard 10-mark assignment. Submit the two Verilog files and
  report as separate bonus materials only if your professor accepts them.
  Do not rename or combine files unless your submission portal requires it.

BUILD C (Linux / Mac)
  gcc -O3 2200405.c -o 2200405

BUILD C (Windows / MinGW GCC)
  gcc -O3 2200405.c -o 2200405.exe

RUN C (Windows example)
  2200405.exe e key.bin plaintext.bin ciphertext.bin
  2200405.exe d key.bin ciphertext.bin recovered.bin

RUN C (Linux example)
  ./2200405 e key.bin plaintext.bin ciphertext.bin
  ./2200405 d key.bin ciphertext.bin recovered.bin

IMPORTANT INPUT/OUTPUT FORMAT
  - key: file containing exactly 8 RAW bytes OR 16 ASCII hex digits
    (with optional whitespace such as a trailing newline).
  - input/output messages: RAW BINARY BYTES, ALWAYS. Do not store the
    plaintext as ASCII hex digits unless those characters are your actual
    plaintext. An 8-byte input represents one DES block.
  - message length must be divisible by 8 bytes; NO padding. A zero-length
    input is permitted, producing zero-length output.
  - for every block, encryption uses the same key (DES-ECB).
  - existing output file is overwritten. Do not point it to an important file.

SAMPLE STANDARD VECTOR
  Key (hex)        : 133457799BBCDFF1
  Plaintext (hex)  : 0123456789ABCDEF
  Ciphertext (hex) : 85E813540F0AB405
  Files store those byte values, NOT the characters of the hex representation.

VERILOG BONUS (Icarus Verilog)
  iverilog -g2012 -s tb_des_core -o sim des_core.v tb_des_core.v
  vvp sim

  Expected: 10 PASS lines and 'ALL 10 TESTS PASSED'.
  A failed case or timeout makes the testbench terminate with a failure status.
  Note: -g2012 is needed for SystemVerilog $fatal in the testbench.

VERIFICATION PERFORMED HERE
  C: compiled with gcc -O3 and strict warning flags, 5 standard DES vectors
  with 3 key encodings in both directions, 60 randomized/adversarial cases
  compared with OpenSSL, invalid-file/CLI tests, and 1 MiB / 16 MiB binary
  roundtrips all passed.
  RTL: all permutation/S-box tables and an independently implemented model
  of the Verilog round/key-schedule logic passed known-answer tests and
  1000 random roundtrips. The Verilog source itself was NOT executed by an
  RTL simulator here; please run the above simulation before claiming
  hardware verification or handing it in as fully verified.

CHANGES RELATIVE TO YOUR UPLOADS
  2200405.c: removed auto-hex guessing for plaintext/ciphertext, switched to
  chunked binary I/O, added input validation and error cleanup, maintained
  standard DES results, and removed compiler warnings.
  des_core.v: UNCHANGED; identical to uploaded file.
  tb_des_core.v: failure/timeout now use $fatal(1,...) instead of finishing
  with a successful exit code; Icarus command updated for -g2012.
  DES Implementation Report.pdf: updated descriptions, test evidence,
  build commands, and qualification about the unrun Verilog simulator.

SECURITY NOTE
  DES/ECB is obsolete for real-world secure communication, but is implemented
  exactly because this course assignment requests it.
