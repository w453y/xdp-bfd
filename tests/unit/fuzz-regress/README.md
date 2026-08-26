Inputs that once crashed tests/unit/dp_fuzz, kept as permanent
regression checks:

    ./tests/unit/dp_fuzz tests/unit/fuzz-regress/*

Each runs in milliseconds. Name new ones for what they broke.

dp_read-off-walk-past-buf
    Out-of-bounds read in dp_read, fixed in 0441f6c. Full account in
    docs/dp-fuzz/README.md.
