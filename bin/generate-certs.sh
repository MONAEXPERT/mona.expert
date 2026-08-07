#!/usr/bin/env bash
# mona.expert — Generate mTLS certificates for wrapper↔website communication
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/../certs"

mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "🔐 mona.expert — Generating mTLS certificates…"

# ─── CA ───────────────────────────────────────────────
echo "  → Internal CA…"
openssl genrsa -out ca-key.pem 4096 2>/dev/null
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem \
  -subj "/C=DE/O=mona.expert/CN=mona.expert Internal CA" 2>/dev/null

# ─── Wrapper server cert ──────────────────────────────
echo "  → Wrapper server cert (127.0.0.1)…"
openssl genrsa -out wrapper-key.pem 2048 2>/dev/null
openssl req -new -key wrapper-key.pem -out wrapper-csr.pem \
  -subj "/C=DE/O=mona.expert/CN=wrapper.mona.expert" 2>/dev/null
openssl x509 -req -days 365 -in wrapper-csr.pem \
  -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out wrapper-cert.pem \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth") 2>/dev/null

# ─── Website client cert ──────────────────────────────
echo "  → Website client cert…"
openssl genrsa -out website-key.pem 2048 2>/dev/null
openssl req -new -key website-key.pem -out website-csr.pem \
  -subj "/C=DE/O=mona.expert/CN=website.mona.expert" 2>/dev/null
openssl x509 -req -days 365 -in website-csr.pem \
  -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out website-cert.pem \
  -extfile <(printf "extendedKeyUsage=clientAuth") 2>/dev/null

# ─── Cleanup ──────────────────────────────────────────
rm -f wrapper-csr.pem website-csr.pem ca-cert.srl

echo ""
echo "✅ Certificates generated in $CERTS_DIR"
echo ""
echo "   CA:           ca-cert.pem (public)"
echo "   CA key:       ca-key.pem (KEEP SECRET — never distribute)"
echo "   Wrapper cert: wrapper-cert.pem + wrapper-key.pem"
echo "   Website cert: website-cert.pem + website-key.pem"
echo ""
echo "   The website uses its cert to authenticate to the wrapper."
echo "   Only clients with a cert signed by this CA can reach the wrapper."
