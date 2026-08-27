#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 NATIVE_ROOT REPORT_DIR" >&2
  exit 2
fi

root=$1
report=$2
bin="${root}/usr/bin"
openssl="${bin}/openssl.exe"
dynamic_smoke="${bin}/openssl-dynamic-smoke.exe"
static_smoke="${bin}/openssl-static-smoke.exe"

mkdir -p "${report}/tls"
cd "${report}"

export PATH="${bin}:${PATH}"
export MSYSTEM=MSYS
export MSYS=winsymlinks:sys
export MSYS2_ARG_CONV_EXCL='*'
export OPENSSL_CONF
OPENSSL_CONF=$(cygpath -w "${root}/usr/ssl/openssl.cnf")
export OPENSSL_MODULES
OPENSSL_MODULES=$(cygpath -w "${root}/usr/lib/ossl-modules")

"${dynamic_smoke}"
"${static_smoke}"

cp "${bin}/dlopen-generic.dll" "${bin}/loadlibrary-dont-resolve.dll"
cp "${bin}/dlopen-generic.dll" "${bin}/loadlibrary-normal.dll"
cp "${bin}/dlopen-generic.dll" "${bin}/dlopen-now.dll"
cp "${bin}/dlopen-generic.dll" "${bin}/dlopen-lazy.dll"

run_loader_control() {
  local name=$1
  shift
  rm -f "${bin}/dllmain-attached.marker"
  set +e
  (
    cd "${bin}"
    "$@"
  ) > "${report}/${name}.out" 2> "${report}/${name}.err"
  local status=$?
  set -e
  if [[ -f "${bin}/dllmain-attached.marker" ]]; then
    cp "${bin}/dllmain-attached.marker" \
      "${report}/${name}.dllmain.marker"
  fi
  printf '%s\t%s\n' "${name}" "${status}" \
    >> loader-controls.tsv
  return "${status}"
}

: > loader-controls.tsv
control_failure=0
run_loader_control loadlibrary-data-dont-resolve \
  ./loadlibrary-smoke.exe ./dlopen-data-only.dll dont-resolve \
  || control_failure=1
run_loader_control loadlibrary-data-normal \
  ./loadlibrary-smoke.exe ./dlopen-data-only.dll normal \
  || control_failure=1
run_loader_control loadlibrary-generic-dont-resolve \
  ./loadlibrary-smoke.exe ./loadlibrary-dont-resolve.dll dont-resolve \
  || control_failure=1
run_loader_control loadlibrary-generic-normal \
  ./loadlibrary-smoke.exe ./loadlibrary-normal.dll normal \
  || control_failure=1
run_loader_control dlopen-nodllmain-now \
  ./dlopen-smoke.exe ./dlopen-nodllmain.dll now \
  || control_failure=1
run_loader_control dlopen-nodllmain-lazy \
  ./dlopen-smoke.exe ./dlopen-nodllmain.dll lazy \
  || control_failure=1
run_loader_control dlopen-generic-now \
  ./dlopen-smoke.exe ./dlopen-now.dll now \
  || control_failure=1
run_loader_control dlopen-generic-lazy \
  ./dlopen-smoke.exe ./dlopen-lazy.dll lazy \
  || control_failure=1
run_loader_control dlopen-crypto-now \
  ./dlopen-smoke.exe ./dlopen-crypto.dll now \
  || control_failure=1
run_loader_control dlopen-crypto-lazy \
  ./dlopen-smoke.exe ./dlopen-crypto.dll lazy \
  || control_failure=1

"${openssl}" version -a > version.txt
grep -F 'OpenSSL 3.5.1' version.txt
grep -F 'OPENSSLDIR: "/usr/ssl"' version.txt
for iteration in 1 2 3; do
  "${openssl}" version > "lifecycle-${iteration}.txt"
  grep -F 'OpenSSL 3.5.1' "lifecycle-${iteration}.txt"
done

run_provider_control() {
  local name=$1
  shift
  set +e
  "${openssl}" list -providers "$@" \
    > "providers-${name}.out" 2> "providers-${name}.err"
  local status=$?
  set -e
  printf '%s\t%s\n' "${name}" "${status}" \
    >> provider-controls.tsv
  return "${status}"
}

: > provider-controls.tsv
default_status=0
legacy_status=0
combined_status=0
minimal_status=0
minimal_provider_dir=$(cygpath -w "${bin}")
run_provider_control default -provider default || default_status=$?
run_provider_control minimal \
  -provider-path "${minimal_provider_dir}" \
  -provider provider-minimal \
  || minimal_status=$?
run_provider_control legacy -provider legacy || legacy_status=$?
run_provider_control combined -provider default -provider legacy \
  || combined_status=$?
[[ "${default_status}" -eq 0 ]] \
  && grep -Eq '^[[:space:]]+default$' providers-default.out \
  || control_failure=1
[[ "${minimal_status}" -eq 0 ]] \
  && grep -Eq '^[[:space:]]+provider-minimal$' providers-minimal.out \
  || control_failure=1
[[ "${legacy_status}" -eq 0 ]] \
  && grep -Eq '^[[:space:]]+legacy$' providers-legacy.out \
  || control_failure=1
[[ "${combined_status}" -eq 0 ]] \
  && grep -Eq '^[[:space:]]+default$' providers-combined.out \
  && grep -Eq '^[[:space:]]+legacy$' providers-combined.out \
  || control_failure=1
if [[ "${control_failure}" -ne 0 ]]; then
  printf 'provider control failure: default=%s minimal=%s legacy=%s combined=%s\n' \
    "${default_status}" "${minimal_status}" \
    "${legacy_status}" "${combined_status}" >&2
  exit 31
fi

printf 'native aarch64-pc-msys OpenSSL\n' > digest-input.txt
expected=$(sha256sum digest-input.txt | cut -d' ' -f1)
"${openssl}" dgst -sha256 digest-input.txt > digest.txt
grep -Fi "${expected}" digest.txt

"${openssl}" speed -seconds 1 -bytes 1024 sha256 \
  > speed.txt 2>&1
grep -Fi 'sha256' speed.txt

cd tls
"${openssl}" req -x509 -newkey rsa:2048 \
  -keyout key.pem \
  -out cert.pem \
  -sha256 \
  -days 1 \
  -nodes \
  -subj /CN=localhost \
  > req.out 2> req.err

"${openssl}" s_server \
  -accept 127.0.0.1:44330 \
  -cert cert.pem \
  -key key.pem \
  -naccept 1 \
  -www \
  > server.out 2> server.err &
server_pid=$!
cleanup() {
  if kill -0 "${server_pid}" 2>/dev/null; then
    powershell.exe -NoProfile -Command \
      "Stop-Process -Id ${server_pid} -ErrorAction SilentlyContinue"
  fi
}
trap cleanup EXIT

sleep 2
printf 'GET / HTTP/1.0\r\n\r\n' \
  | "${openssl}" s_client \
      -connect 127.0.0.1:44330 \
      -CAfile cert.pem \
      -verify_return_error \
      > client.out 2> client.err
wait "${server_pid}"
trap - EXIT

cat client.out client.err > client.combined
grep -F 'Verification: OK' client.combined
grep -Eq 'TLSv1\.[23]' client.combined

printf 'native-arm64-openssl=pass\n'
