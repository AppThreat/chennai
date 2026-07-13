# Hold-out Corpus
#
# This directory is reserved for held-out corpus cases that are NOT used during
# development or tuning. Cases here must not be moved to the main corpus/
# directory until a formal evaluation cycle is declared.
#
# CONTAMINATION GUARD: Do not reference cases in this directory when writing
# prompts, tuning thresholds, or adjusting CWE-family mappings. Doing so
# invalidates the hold-out split and risks overfitting.
#
# To add a case:
#   1. Create a subdirectory with the same structure as corpus/<case>/.
#   2. Add a case.toml with ground truth.
#   3. Do NOT run `chennai-bench score` against this directory.
