# Abuse cases

How someone might try to use this tool for something it should not do, and what
happens when they try. Each row has a test; the tool's refusal is executable,
not editorial.

| # | Attempt | What the tool does | Test |
| --- | --- | --- | --- |
| **AB-1** | "Crack this PDF for me" | No such capability exists. There is no candidate loop, no wordlist support, no retry. A test asserts the package exposes no symbol matching `crack`, `bruteforce`, `wordlist`, `dictionary_attack`, `guess`. | `test_no_bypass.py::test_no_password_guessing_helper_exists` |
| **AB-2** | Script the CLI in a loop over a password list | Each invocation makes exactly **one** attempt and exits 3. Nothing about the tool makes this faster than any other wrong-password path, and the failure carries no oracle beyond "wrong". | `test_no_bypass.py::test_a_wrong_password_is_never_retried` |
| **AB-3** | Strip printing/copying restrictions from a PDF without the owner password | Refused, exit 10, with an explanation of what the file actually is. qpdf itself rejects a wrong owner password, so there is no way through even with the flag. | `test_no_bypass.py::test_restriction_stripping_without_the_owner_password_is_refused` |
| **AB-4** | Remove "Restrict editing" from a Word document | Refused with or without `--remove-restrictions`. The content is not encrypted and the password is only a hash; removal would mean deleting an XML element unchecked. The message points at Word's own *Stop Protection*. | `test_no_bypass.py::test_office_editing_restrictions_are_never_stripped` |
| **AB-5** | Remove DRM from an ebook or a rights-managed document | Not implemented and never will be. Detected, named, and refused with the reason. | `test_no_bypass.py::test_drm_is_reported_as_permanently_out_of_scope` |
| **AB-6** | Use the tool on a file found on a shared drive | Out of software's reach. The tool enforces possession of the password, which is the only thing it can check. Stated plainly in the README rather than implied. | — |
| **AB-7** | Use an untested code path and blame the tool for the result | Legacy Office decryption is gated behind `--experimental`, warns in detection, in the result, and in the docs. | `test_no_bypass.py::test_legacy_office_is_gated_behind_experimental` |
| **AB-8** | Feed a decompression bomb to exhaust the machine | Refused at 16 GiB total or 2000:1 per entry, checked while streaming, before the disk fills. | `test_zip.py::test_decompression_bomb_is_refused` |
| **AB-9** | Craft an archive that writes outside the extraction directory | 7z entry names are validated for absolute paths and `..` before anything is extracted. | `adapters/sevenzip.py`, `_unsafe()` |
| **AB-10** | Read another user's password out of `ps` | There is no argv route. | `test_cli.py::test_password_on_argv_is_refused_with_a_reason` |
| **AB-11** | Recover a password from the tool's output or logs | Nothing logs it; error messages carry no password material; `repr()` is a placeholder; a debug-level run over a failing file is asserted not to contain it. | `test_no_leaks.py` |
| **AB-12** | Trick the tool into overwriting the original | Output defaults to a new name; an existing output is refused without `--overwrite`; `--in-place` is explicit and still verifies before replacing. | `test_engine.py` |
| **AB-13** | Rename a file to dodge a policy check | Identification is by content. A renamed file is handled correctly **and** the mismatch is reported. | `test_detection.py::test_renaming_a_file_does_not_change_what_it_is` |
| **AB-14** | Get a "success" for a file that did not really decrypt | The output is re-read from disk and its invariants compared before anything is published; a mismatch scrubs the file and exits 9. | `test_pdf.py::test_verification_failure_discards_the_output` |

## The one we cannot solve

**AB-6.** No local tool can tell whether the person holding a password is
entitled to it. This is true of every decryption tool ever written, including
the applications that created these files. What a tool *can* do is refuse the
operations that do not require a password at all — which is what
[ADR-0008](../adr/0008-owner-restriction-policy.md) is about, and what
separates this from the "unlocker" sites.

## If you find a way around one of these

Report it as a security issue — see [SECURITY.md](../../SECURITY.md). A bypass
of the policy layer is a vulnerability in this project even though it does not
expose anyone's data, because the policy layer is the product.
