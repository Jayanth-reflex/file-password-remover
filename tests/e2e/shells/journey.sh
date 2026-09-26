#!/bin/sh
# One user journey, written in the shell's own idioms, run under sh, dash, bash
# and zsh. Plain POSIX on purpose: every construct here must mean the same
# thing in all four, so the script only exercises what they have in common.
#
#   journey.sh FPR WORKDIR ODD_NAME
#
# WORKDIR holds the fixtures written by tests/e2e/test_shells.py. ODD_NAME is a
# file name with non-ASCII characters in it, passed in rather than typed here so
# the script's own encoding cannot matter.

FPR=$1
cd "$2" || exit 1
ODD=$3
ODD_OUT=$(printf '%s' "$ODD" | sed 's/\.pdf$/-unprotected.pdf/')
PW='correct horse battery staple'

fail() {
    printf 'FAIL: %s\n' "$*"
    exit 1
}

step() {
    printf '== %s\n' "$*"
}

step 'the menu'
code=$("$FPR" >menu.log 2>&1; echo $?)
[ "$code" = 2 ] || fail "menu exited $code, expected 2"
grep -q 'reads only' menu.log || fail 'menu does not say what inspect does'

step 'version and formats'
"$FPR" --version | grep -q '^fpr [0-9]' || fail 'version'
"$FPR" formats >/dev/null || fail 'formats'

step 'inspect needs no password'
"$FPR" inspect locked.pdf >/dev/null </dev/null || fail 'inspect'

step 'remove with the password in a file'
"$FPR" remove locked.pdf --password-file pw.txt >/dev/null || fail 'remove --password-file'
[ -f locked-unprotected.pdf ] || fail 'no output from --password-file'

step 'remove with the password on descriptor 3'
"$FPR" remove locked.pdf --password-fd 3 -o via-fd.pdf 3<pw.txt >/dev/null || fail 'remove --password-fd'
[ -f via-fd.pdf ] || fail 'no output from --password-fd'

step 'remove with the password piped on stdin'
printf '%s' "$PW" | "$FPR" remove archive.zip --password-stdin >/dev/null || fail 'remove --password-stdin'

step 'a wrong password exits 3 and writes nothing'
code=$(printf '%s' 'not it' | "$FPR" remove locked.pdf --password-stdin -o nope.pdf >/dev/null 2>&1; echo $?)
[ "$code" = 3 ] || fail "wrong password exited $code, expected 3"
[ ! -f nope.pdf ] || fail 'an output was written for a wrong password'

step 'protect with a generated password, then open it again'
"$FPR" protect plain.pdf --generate --password-out gen.txt >/dev/null || fail 'protect --generate'
"$FPR" remove plain-protected.pdf --password-file gen.txt -o reopened.pdf >/dev/null || fail 'reopen'
[ -f reopened.pdf ] || fail 'the generated password did not reopen the file'

step 'json on stdout'
"$FPR" --json inspect locked.pdf | grep -q '"protection"' || fail 'json'

step 'a name with spaces'
"$FPR" remove 'with spaces.pdf' --password-file pw.txt >/dev/null || fail 'spaces'
[ -f 'with spaces-unprotected.pdf' ] || fail 'no output for a name with spaces'

step 'a name that is not ASCII'
"$FPR" remove "$ODD" --password-file pw.txt >/dev/null || fail 'non-ASCII name'
[ -f "$ODD_OUT" ] || fail 'no output for a non-ASCII name'

step 'the exit code reaches the shell'
"$FPR" remove plain.pdf --password-file pw.txt >/dev/null 2>&1
code=$?
[ "$code" = 6 ] || fail "nothing-to-remove exited $code, expected 6"

echo 'JOURNEY OK'
