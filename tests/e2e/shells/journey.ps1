# One user journey in PowerShell idioms, run under both PowerShell 7 (pwsh, on
# every OS) and Windows PowerShell 5.1 (powershell.exe). The two differ in
# exactly the places this exercises: `>` writes UTF-16 with a byte-order mark in
# 5.1 and UTF-8 in 7, and a pipeline into a native command appends a newline
# in an encoding chosen by $OutputEncoding.
#
#   journey.ps1 -Fpr FPR -Work WORKDIR -Odd ODD_NAME

param(
    [Parameter(Mandatory)] [string] $Fpr,
    [Parameter(Mandatory)] [string] $Work,
    [Parameter(Mandatory)] [string] $Odd
)

# Not 'Stop': in 5.1 a native command writing to stderr would then throw, and
# exit codes are what this is checking.
$ErrorActionPreference = 'Continue'
Set-Location -LiteralPath $Work
$Password = 'correct horse battery staple'

function Fail([string] $Message) {
    Write-Output "FAIL: $Message"
    exit 1
}

function Step([string] $Message) {
    Write-Output "== $Message"
}

function Expect-Code([int] $Want, [string] $What) {
    if ($LASTEXITCODE -ne $Want) { Fail "$What exited $LASTEXITCODE, expected $Want" }
}

Step 'the menu'
$menu = & $Fpr 2>&1 | Out-String
Expect-Code 2 'menu'
if ($menu -notmatch 'reads only') { Fail 'menu does not say what inspect does' }

Step 'version and formats'
$version = & $Fpr --version
Expect-Code 0 'version'
if ($version -notmatch '^fpr \d') { Fail "version printed '$version'" }
& $Fpr formats | Out-Null
Expect-Code 0 'formats'

Step 'inspect needs no password'
& $Fpr inspect locked.pdf | Out-Null
Expect-Code 0 'inspect'

Step 'a password file written the PowerShell way'
# UTF-16LE with a BOM in 5.1, UTF-8 in 7. Both must be read as the password.
$Password > pw-native.txt
& $Fpr remove locked.pdf --password-file pw-native.txt -o via-native-file.pdf | Out-Null
Expect-Code 0 'remove --password-file (PowerShell-written file)'

Step 'a password piped from PowerShell'
$Password | & $Fpr remove archive.zip --password-stdin | Out-Null
Expect-Code 0 'remove --password-stdin (pipeline)'

Step 'a wrong password exits 3 and writes nothing'
'not it' | & $Fpr remove locked.pdf --password-stdin -o nope.pdf 2>$null | Out-Null
Expect-Code 3 'wrong password'
if (Test-Path -LiteralPath nope.pdf) { Fail 'an output was written for a wrong password' }

Step 'protect with a generated password, then open it again'
& $Fpr protect plain.pdf --generate --password-out gen.txt | Out-Null
Expect-Code 0 'protect --generate'
& $Fpr remove plain-protected.pdf --password-file gen.txt -o reopened.pdf | Out-Null
Expect-Code 0 'reopen with the generated password'

Step 'json parses as PowerShell objects'
$report = (& $Fpr --json inspect locked.pdf | Out-String) | ConvertFrom-Json
Expect-Code 0 'json inspect'
if ($report.results[0].protection -eq 'none') { Fail 'json says an encrypted file is unprotected' }

Step 'a name with spaces'
& $Fpr remove 'with spaces.pdf' --password-file pw.txt | Out-Null
Expect-Code 0 'spaces'
if (-not (Test-Path -LiteralPath 'with spaces-unprotected.pdf')) { Fail 'no output for a name with spaces' }

Step 'a name that is not ASCII'
& $Fpr remove $Odd --password-file pw.txt | Out-Null
Expect-Code 0 'non-ASCII name'
$oddOut = $Odd -replace '\.pdf$', '-unprotected.pdf'
if (-not (Test-Path -LiteralPath $oddOut)) { Fail 'no output for a non-ASCII name' }

Step 'the exit code reaches the shell'
& $Fpr remove plain.pdf --password-file pw.txt 2>$null | Out-Null
Expect-Code 6 'nothing to remove'

Write-Output 'JOURNEY OK'
exit 0
