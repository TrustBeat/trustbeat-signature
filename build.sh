#!/usr/bin/env bash
# Builds static trustbeat-signature binaries for every supported OS/arch and packs each into a
# release archive (tar.gz, zip for Windows) with README.md, LICENSE and THIRD_PARTY_LICENSES.txt —
# the licence texts of every Go module linked into the binaries. Writes dist/SHA256SUMS over the
# archives. Usage: ./build.sh [version]   (defaults to `git describe`)
# The toolchain is pinned by go.mod; GOTOOLCHAIN=local refuses a silent download of another one.
set -euo pipefail
cd "$(dirname "$0")"
version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
version="${version#v}"
export GOTOOLCHAIN=local CGO_ENABLED=0
max_bytes=$((20 * 1024 * 1024))
rm -rf dist && mkdir -p dist/bin

targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
for target in $targets; do
  os="${target%/*}" arch="${target#*/}"
  out="dist/bin/trustbeat-signature-${os}-${arch}"
  [[ "$os" == windows ]] && out+=".exe"
  GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=${version}" -o "$out" .
  size=$(wc -c <"$out")
  if (( size > max_bytes )); then
    echo "$out is $size bytes, over the ${max_bytes}-byte budget" >&2
    exit 1
  fi
  printf '%-55s %8d bytes\n' "$out" "$size"
done

# Licences of the modules actually linked (union over all targets: x/sys differs per OS).
licences=dist/THIRD_PARTY_LICENSES.txt
{
  echo "trustbeat-signature ${version} links the following Go modules. Their licence texts follow."
  echo
  for mod in $(go version -m dist/bin/* | awk '$1 == "dep" { print $2 "@" $3 }' | sort -u); do
    dir=$(go mod download -json "$mod" | sed -n 's/^\t"Dir": "\(.*\)",$/\1/p')
    files=$(find "$dir" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) | sort)
    if [[ -z "$files" ]]; then
      echo "no licence file found for $mod" >&2
      exit 1
    fi
    for f in $files; do
      printf '================================================================================\n'
      printf '%s — %s\n' "$mod" "$(basename "$f")"
      printf '================================================================================\n\n'
      cat "$f"
      echo
    done
  done
  printf '================================================================================\n'
  printf 'Go standard library (%s) — LICENSE\n' "$(go env GOVERSION)"
  printf '================================================================================\n\n'
  cat "$(go env GOROOT)/LICENSE"
} >"$licences"

for target in $targets; do
  os="${target%/*}" arch="${target#*/}"
  stem="trustbeat-signature-${version}-${os}-${arch}"
  mkdir -p "dist/${stem}"
  if [[ "$os" == windows ]]; then
    cp "dist/bin/trustbeat-signature-${os}-${arch}.exe" "dist/${stem}/trustbeat-signature.exe"
  else
    cp "dist/bin/trustbeat-signature-${os}-${arch}" "dist/${stem}/trustbeat-signature"
  fi
  cp README.md LICENSE "$licences" "dist/${stem}/"
  # Fixed timestamps and order, so an archive is a function of its inputs.
  touch -d "@0" "dist/${stem}" "dist/${stem}"/*
  if [[ "$os" == windows ]]; then
    (cd dist && zip -qX -r "${stem}.zip" "${stem}")
  else
    tar -C dist --sort=name --owner=0 --group=0 --numeric-owner --mtime=@0 -cf - "${stem}" | gzip -n >"dist/${stem}.tar.gz"
  fi
  rm -rf "dist/${stem}"
done
rm -rf dist/bin
(cd dist && sha256sum trustbeat-signature-* >SHA256SUMS && cat SHA256SUMS)
