# File Password Remover -- container image for the CLI.
#
# Why this image exists: the threat model's R-08 says the parsers are not
# sandboxed and recommends processing untrusted files in a container. This is
# that container, so the recommendation is something you can run rather than
# something you have to build yourself.
#
#   docker run --rm -v "$PWD:/data" ghcr.io/jayanth-reflex/file-password-remover \
#       inspect /data/report.pdf
#
#   printf '%s' "$PW" | docker run --rm -i -v "$PWD:/data" \
#       ghcr.io/jayanth-reflex/file-password-remover \
#       remove /data/report.pdf --password-stdin
#
# The image deliberately does NOT include py7zr: it is LGPL-2.1-or-later and
# the default distribution stays permissive-only (docs/adr/0006-...). Add it
# yourself with a one-line derived image if you need .7z support.

# ---------------------------------------------------------------- build ---
FROM python:3.12-slim AS build

WORKDIR /src
RUN python -m pip install --no-cache-dir --upgrade pip build

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

# -------------------------------------------------------------- runtime ---
FROM python:3.12-slim

LABEL org.opencontainers.image.title="File Password Remover" \
      org.opencontainers.image.description="Remove password protection from files you own, locally, after you supply the correct password. No uploads, no telemetry, verified output." \
      org.opencontainers.image.source="https://github.com/Jayanth-reflex/file-password-remover" \
      org.opencontainers.image.documentation="https://github.com/Jayanth-reflex/file-password-remover#readme" \
      org.opencontainers.image.licenses="Apache-2.0"

# No build toolchain in the final image: every dependency has a manylinux wheel.
COPY --from=build /dist/*.whl /tmp/
RUN python -m pip install --no-cache-dir /tmp/*.whl \
 && rm -rf /tmp/*.whl \
 && python -c "import fpr, pikepdf, msoffcrypto, pyzipper; print('fpr', fpr.__version__)"

# Run as a non-root user. The tool needs no privileges, and a decryption tool
# least of all.
RUN useradd --create-home --uid 10001 fpr
USER fpr
WORKDIR /data

ENTRYPOINT ["fpr"]
CMD ["--help"]
