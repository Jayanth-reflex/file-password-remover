@echo off
rem One user journey in cmd.exe idioms: %ERRORLEVEL%, `<` redirection, and
rem `echo value| command`, which sends the value followed by CRLF.
rem
rem   journey.cmd FPR WORKDIR ODD_NAME
rem
rem Checks go through :expect rather than parenthesised blocks, because
rem %ERRORLEVEL% inside a block is expanded when the block is parsed, before
rem any command in it has run.

setlocal
set "FPR=%~1"
cd /d "%~2" || exit /b 1
set "ODD=%~3"

echo == the menu
"%FPR%" > menu.log 2>&1
call :expect 2 "menu" || exit /b 1
findstr /c:"reads only" menu.log > nul || (echo FAIL: menu does not say what inspect does& exit /b 1)

echo == version and formats
"%FPR%" --version > version.log
call :expect 0 "version" || exit /b 1
"%FPR%" formats > nul
call :expect 0 "formats" || exit /b 1

echo == inspect needs no password
"%FPR%" inspect locked.pdf > nul
call :expect 0 "inspect" || exit /b 1

echo == remove with the password in a file
"%FPR%" remove locked.pdf --password-file pw.txt > nul
call :expect 0 "remove --password-file" || exit /b 1
if not exist locked-unprotected.pdf (echo FAIL: no output from --password-file& exit /b 1)

echo == remove with the password redirected into stdin
"%FPR%" remove archive.zip --password-stdin < pw.txt > nul
call :expect 0 "remove --password-stdin with <" || exit /b 1

echo == remove with the password echoed into a pipe
echo correct horse battery staple| "%FPR%" remove locked.pdf --password-stdin -o via-echo.pdf > nul
call :expect 0 "remove with echo ...|" || exit /b 1

echo == a wrong password exits 3 and writes nothing
echo not it| "%FPR%" remove locked.pdf --password-stdin -o nope.pdf > nul 2>&1
call :expect 3 "wrong password" || exit /b 1
if exist nope.pdf (echo FAIL: an output was written for a wrong password& exit /b 1)

echo == protect with a generated password, then open it again
"%FPR%" protect plain.pdf --generate --password-out gen.txt > nul
call :expect 0 "protect --generate" || exit /b 1
"%FPR%" remove plain-protected.pdf --password-file gen.txt -o reopened.pdf > nul
call :expect 0 "reopen with the generated password" || exit /b 1

echo == json on stdout
"%FPR%" --json inspect locked.pdf > report.json
call :expect 0 "json inspect" || exit /b 1
findstr /c:"\"protection\"" report.json > nul || (echo FAIL: json& exit /b 1)

echo == a name with spaces
"%FPR%" remove "with spaces.pdf" --password-file pw.txt > nul
call :expect 0 "spaces" || exit /b 1
if not exist "with spaces-unprotected.pdf" (echo FAIL: no output for a name with spaces& exit /b 1)

echo == a name that is not ASCII
"%FPR%" remove "%ODD%" --password-file pw.txt > nul
call :expect 0 "non-ASCII name" || exit /b 1

echo == the exit code reaches the shell
"%FPR%" remove plain.pdf --password-file pw.txt > nul 2>&1
call :expect 6 "nothing to remove" || exit /b 1

echo JOURNEY OK
exit /b 0

:expect
if "%ERRORLEVEL%"=="%~1" exit /b 0
echo FAIL: %~2 exited %ERRORLEVEL%, expected %~1
exit /b 1
