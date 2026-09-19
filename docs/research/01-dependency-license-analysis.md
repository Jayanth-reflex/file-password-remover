# Dependency licence and advisory analysis

Every figure here was read from a primary source on **2026-09-19** and the raw
responses are kept in [`evidence/`](evidence/). Licences come from the
installed distributions' own metadata (`License-Expression` / `License`
classifiers and the `licenses/` directory inside each wheel), not from a
summary site. Advisories come from a direct query to the
[OSV](https://osv.dev) API for each pinned version.

Reproduce it:

```bash
python scripts/audit_dependencies.py            # rewrites docs/research/evidence/*.json
pip-audit                                        # cross-check against PyPI advisories
```

## Runtime dependencies of the default install

| Distribution | Version | Licence (SPDX) | Copyleft? | Source |
| --- | --- | --- | --- | --- |
| `pikepdf` | 10.13.0.post1 | `MPL-2.0` | File-level (weak) | [github.com/pikepdf/pikepdf](https://github.com/pikepdf/pikepdf) |
| ↳ qpdf (in the wheel) | 12.3.2 | `Apache-2.0` | No | [github.com/qpdf/qpdf](https://github.com/qpdf/qpdf) |
| ↳ libjpeg-turbo (in the wheel) | varies by platform | IJG + `BSD-3-Clause` + `Zlib` | No | [libjpeg-turbo.org](https://libjpeg-turbo.org/) |
| ↳ OpenSSL (Windows wheel only, static) | 3.6.0 | `Apache-2.0` | No | [openssl.org](https://www.openssl.org/) |
| `msoffcrypto-tool` | 6.0.0 | `MIT` | No | [github.com/nolze/msoffcrypto-tool](https://github.com/nolze/msoffcrypto-tool) |
| `pyzipper` | 0.4.0 | `MIT` | No | [github.com/danifus/pyzipper](https://github.com/danifus/pyzipper) |
| `cryptography` | 50.0.1 | `Apache-2.0 OR BSD-3-Clause` | No | [github.com/pyca/cryptography](https://github.com/pyca/cryptography) |
| `olefile` | 0.47 | `BSD-2-Clause` | No | [decalage.info](https://www.decalage.info/python/olefileio) |
| `lxml` | 6.1.3 | `BSD-3-Clause` | No | [lxml.de](https://lxml.de/) |
| `pycryptodomex` | 3.23.0 | `BSD-2-Clause` + Public Domain | No | [pycryptodome.org](https://www.pycryptodome.org) |
| `Pillow` | 12.3.0 | `MIT-CMU` | No | [python-pillow.github.io](https://python-pillow.github.io) |

## Optional extra

| Distribution | Version | Licence | Why it is optional |
| --- | --- | --- | --- |
| `py7zr` | 1.1.3 | `LGPL-2.1-or-later` | See [ADR-0006](../adr/0006-optional-lgpl-sevenzip-extra.md) |

## Obligations this project actually has

**MPL-2.0 (pikepdf).** File-level copyleft. We do not modify pikepdf's source,
so the obligation is to keep its licence notice with any distribution and to
say where the source is. Both are done in [`NOTICE`](../../NOTICE). MPL-2.0
explicitly permits combining with larger works under other licences.

**Apache-2.0 (qpdf, cryptography, OpenSSL on Windows).** Attribution and a
copy of the licence. `NOTICE` carries it; the wheels carry their own texts.

**MIT / BSD (msoffcrypto-tool, pyzipper, olefile, lxml, pycryptodomex,
Pillow).** Attribution only.

**IJG (libjpeg-turbo, inside pikepdf's wheels).** Requires its README to
accompany redistribution. pikepdf ships it inside the wheel, so anything that
redistributes the wheel — including a PyInstaller bundle — satisfies this as
long as the `dist-info` directory is preserved.
`packaging/pyinstaller/fpr.spec` keeps the metadata directories for exactly
this reason.

**LGPL-2.1-or-later (py7zr).** Not installed by default and **not bundled in
released binaries**. When a user opts into the extra with
`pip install "file-password-remover[sevenzip]"`, py7zr is installed as a
separate, user-replaceable distribution — which is the form of use LGPL §6 is
happiest with. Bundling it into a frozen single-file binary would create a
relinking obligation we do not want to take on for one optional format.

**GPL-3.0-with-GCC-Runtime-Exception** appears in pikepdf's musllinux wheels
only (libstdc++/libgcc). The Runtime Library Exception exists precisely to
permit this; no obligation flows to us.

## Vulnerability status

Queried against OSV for each pinned version on 2026-09-19; raw response in
[`evidence/osv-scan-deps.json`](evidence/osv-scan-deps.json).

| Distribution | Version | Known advisories |
| --- | --- | --- |
| pikepdf | 10.13.0.post1 | 0 |
| msoffcrypto-tool | 6.0.0 | 0 |
| pyzipper | 0.4.0 | 0 |
| py7zr | 1.1.3 | 0 |
| cryptography | 50.0.1 | 0 |
| olefile | 0.47 | 0 |
| lxml | 6.1.3 | 0 |
| pycryptodomex | 3.23.0 | 0 |
| Pillow | 12.3.0 | 0 |

`pip-audit` agrees: *"No known vulnerabilities found"*. Both checks run on
every CI job and weekly on a schedule
([`.github/workflows/security.yml`](../../.github/workflows/security.yml)),
because "zero today" is a statement with a shelf life.

## Maintenance risk, stated plainly

- **pyzipper** went four years between 0.3.6 (2022-07-31) and 0.4.0
  (2026-05-14). If it were abandoned, WinZip AES support would need to move to
  our own implementation on top of `cryptography` — a few hundred lines, since
  the format is small and frozen. Recorded as risk **R-11**.
- **olefile** last released 0.47 in December 2023 and is read-only in our use.
  Low risk; the format has not changed since 1997.
- **msoffcrypto-tool** has one maintainer. Its encryption path is already known
  to be broken in 6.0.0, which is a signal worth watching. Our exposure is
  limited to the decryption path, which is well exercised by our own
  independently generated fixtures.
