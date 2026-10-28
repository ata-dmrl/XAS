#!/usr/bin/env bash
# XAS başlatıcı (Linux/macOS). Çift tıklanabilir ya da ./xas.sh ile çalışır.
# bin/xas.js ilk çalıştırmada eksik bağımlılıkları kendisi kurar.
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js bulunamadı. Kurun: https://nodejs.org/"
  exit 1
fi

exec node "$DIR/bin/xas.js" "$@"
