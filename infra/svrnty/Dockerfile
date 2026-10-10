# ── Satellite blind-router image ──────────────────────────────────────
# Multi-stage: the deployed python:3.12-slim has NO liboqs, and liboqs-python
# needs the C lib. Builder compiles liboqs 0.16.0 ML-KEM-1024-ONLY (small/fast);
# the final stage copies just the .so. ML-KEM-1024 decap is lazy-imported inside
# the onion peel path (mailbox_envelope.py) and fail-fast self-checked at startup
# (satellite_keys.verify_mlkem_available) — a broken liboqs must NOT silently
# 400-storm /onion.
#
# VERSION PAIR (MATCHED, no ABI skew ships): liboqs C 0.16.0 +
# liboqs-python 0.16.0.1. Re-KAT the ACTUAL built image (@noble→oqs
# ML-KEM-1024 interop + §5 combiner, byte-identical to his pinned FIPS-203
# vectors 1568/3168/1568) BEFORE blessing the commit. FIPS 203 is final → bytes
# are version-stable; trust-but-verify.

# builder: compile liboqs 0.16.0, ML-KEM-1024 only (matched to the 0.16.0.1 wrapper)
FROM python:3.12-slim AS oqs-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build git ca-certificates libssl-dev \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
 && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
      -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_MINIMAL_BUILD="KEM_ml_kem_1024" \
      -DCMAKE_INSTALL_PREFIX=/opt/oqs \
 && ninja -C /tmp/liboqs/build install

# final
FROM python:3.12-slim
WORKDIR /app
# liboqs (built with OpenSSL) dynamically links libcrypto at runtime — install the
# RUNTIME OpenSSL lib EXPLICITLY (hardening pt1: libssl-dev above is build-time
# headers only; don't rely on the base image happening to carry libssl3).
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=oqs-builder /opt/oqs/lib/ /usr/local/lib/
RUN ldconfig
# Matched pair, all pip deps pinned EXACT for a reproducible
# crypto build. C lib pinned to the 0.16.0 git tag above. FOLLOW-UP before deploy commit
# (hardening pt2): add --require-hashes with a fully-resolved hashed requirements.txt
# (incl. transitive deps) for supply-chain integrity. Versions below captured via pip freeze.
RUN pip install --no-cache-dir \
      fastapi==0.142.2 uvicorn==0.54.0 pydantic==2.13.5 \
      cryptography==50.0.2 liboqs-python==0.16.0.1
ENV OQS_INSTALL_PATH=/usr/local

# crypto_utils.py (satellite.py imports it) + chat.html (served surface) live in the BOX
# build ctx (satellite-dev/), synced by svrnty_deploy.sh — NOT in the local infra/satellite
# tree (local crypto_utils.py is a different 10506B file; chat.html is box-only). Build on box.
COPY satellite.py mailbox_envelope.py satellite_keys.py crypto_utils.py dashboard.html chat.html ./

# Non-root (hardening pt3 — the relay is internet-facing). The persistent /data volume
# (SQLite DB + SATELLITE_KEY_PATH keypair, minted 0600 on first start) must be writable by
# uid 10001. Pre-create + chown /data IN THE IMAGE so a FRESH named volume inherits satellite
# ownership (Docker seeds a fresh empty volume from the image mountpoint) — else a self-hoster
# doing `docker compose up` on a fresh volume hits a root-owned /data the non-root relay cannot
# write → "unable to open database file" startup crash (hardened read_only makes it worse, not
# the cause). Existing non-empty volumes are untouched by this.
RUN useradd -r -u 10001 satellite \
 && mkdir -p /data && chown satellite:satellite /data
USER satellite

ENV SATELLITE_MODE=full
EXPOSE 8101

# Use python3 (always present in this image) — the slim base has NO wget/curl, so a wget
# healthcheck false-reports "unhealthy" while the app is actually serving 200 (a 376-fail
# streak was observed on a live-in-use dev-satellite 2026-09-03 — cosmetic but misleading).
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8101/health', timeout=4).status==200 else 1)" || exit 1

# --no-access-log: linkable ids (route_id, mailbox_fp, fingerprint) ride in URL
# PATHS, so uvicorn's default access log would RECORD exactly the correlation data the K1 blinding
# hides (deposit-route-X ↔ poll-route-X, mailbox_fp↔IP). A blind relay must be unable to
# deanonymize its own traffic BY CONSTRUCTION — the relay operator is untrusted in federation.
CMD ["uvicorn", "satellite:app", "--host", "0.0.0.0", "--port", "8101", "--no-access-log"]
