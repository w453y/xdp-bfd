#!/bin/bash
# Style checks, as FRR runs them: clang-format and checkpatch on C, black on
# Python. Exits non-zero on any finding.
#
#     tools/checkstyle.sh
#
# CLANG_FORMAT and CHECKPATCH override the tools; checkpatch.pl is otherwise
# fetched from FRR at a pinned commit.
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2

CLANG_FORMAT=${CLANG_FORMAT:-$(command -v clang-format-21 || command -v clang-format)}
FRR_COMMIT=a37b548b3eddb86bc3375a98daf36c44e0fb1379
CHECKPATCH_SHA256=16fd5c28b0ab1c4d15308b9b81b235e43a13c99bb8dbd0610853a9b35807377f

# Rules that do not apply here:
#   SNPRINTF          asks for FRR's snprintfrr(), which is libfrr only
#   VOLATILE          volatile sig_atomic_t is the correct signal flag type
#   STRCPY, STRNCPY   strlcpy() needs glibc 2.38; Debian 12 and EL9 are older
#   COMPLEX_MACRO     BFD_STAT_LIST is an X-macro and cannot be parenthesised
#   OPEN_BRACE        clang-format enforces braces; checkpatch misreads the
#                     SHA1_UNROLL pragma line as a function header
#   EMBEDDED_FUNCTION_NAME  "main loop" in a log line inside main()
IGNORE=SNPRINTF,VOLATILE,STRCPY,STRNCPY,COMPLEX_MACRO,OPEN_BRACE,EMBEDDED_FUNCTION_NAME

if [ -z "${CHECKPATCH:-}" ]; then
	CHECKPATCH=${XDG_CACHE_HOME:-$HOME/.cache}/xdp-bfd/checkpatch-$FRR_COMMIT.pl
	if [ ! -f "$CHECKPATCH" ]; then
		mkdir -p "$(dirname "$CHECKPATCH")"
		curl -sfL -o "$CHECKPATCH.tmp" \
			"https://raw.githubusercontent.com/FRRouting/frr/$FRR_COMMIT/tools/checkpatch.pl" ||
			{ echo "checkstyle: cannot fetch checkpatch.pl; set CHECKPATCH" >&2; exit 2; }
		echo "$CHECKPATCH_SHA256  $CHECKPATCH.tmp" | sha256sum -c --quiet ||
			{ rm -f "$CHECKPATCH.tmp"; exit 2; }
		mv "$CHECKPATCH.tmp" "$CHECKPATCH"
	fi
fi

fail=0
c_files=$(git ls-files '*.c' '*.h')
py_files=$(git ls-files '*.py')

echo "clang-format ($($CLANG_FORMAT --version | grep -o 'version [0-9.]*'))"
$CLANG_FORMAT --dry-run --Werror $c_files || fail=1

echo "checkpatch (FRR ${FRR_COMMIT:0:10})"
for f in $c_files; do
	perl "$CHECKPATCH" --no-tree -f --terse --no-summary --ignore "$IGNORE" \
		--typedefsfile tools/checkpatch.typedefs "$f" || fail=1
done

echo "black ($(python3 -m black --version | head -1))"
python3 -m black --check --quiet $py_files || fail=1

[ $fail -eq 0 ] && echo "style: clean"
exit $fail
