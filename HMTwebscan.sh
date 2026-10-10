#!/usr/bin/env bash
set -uo pipefail
# ============================================================
# INTERNAL WEBSITE ASSESSMENT
# Automated Security Testing & Vulnerability Assessment v5.0
# Nmap + DNS + HTTP + TLS + Nikto + httpx + WhatWeb + testssl.sh +
# Subfinder + dnsx + Katana + ffuf + WPScan + Nuclei + OWASP ZAP
# ============================================================
# ============================================================
# TARGET / PATH CONFIGURATION
# Usage:
#   ./HMTwebscan.sh https://example.com
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_BASE="${SCRIPT_DIR}/reports"

# Scan profile: fast | standard | full
# Default keeps the existing behavior as the baseline while adding optional scanners.
SCAN_PROFILE="${SCAN_PROFILE:-standard}"
ENABLE_SUBDOMAIN="${ENABLE_SUBDOMAIN:-1}"
ENABLE_CRAWL="${ENABLE_CRAWL:-1}"
ENABLE_FUZZ="${ENABLE_FUZZ:-0}"
ENABLE_WPSCAN="${ENABLE_WPSCAN:-1}"
ENABLE_ACTIVE_ZAP="${ENABLE_ACTIVE_ZAP:-0}"
NUCLEI_PROFILE="${NUCLEI_PROFILE:-standard}"
FUZZ_WORDLIST="${FUZZ_WORDLIST:-}"
ALLOW_PRIVATE_TARGET="${ALLOW_PRIVATE_TARGET:-0}"
ALLOW_CROSS_HOST_REDIRECTS="${ALLOW_CROSS_HOST_REDIRECTS:-0}"
STEP_TIMEOUT="${STEP_TIMEOUT:-1800}"
HTTP_TIMEOUT="${HTTP_TIMEOUT:-30}"
MAX_CRAWL_DEPTH="${MAX_CRAWL_DEPTH:-3}"
MAX_CRAWL_URLS="${MAX_CRAWL_URLS:-5000}"
MAX_SURFACE_TARGETS="${MAX_SURFACE_TARGETS:-750}"
NUCLEI_IMAGE="${NUCLEI_IMAGE:-projectdiscovery/nuclei:latest}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
I_HAVE_AUTHORIZATION="${I_HAVE_AUTHORIZATION:-NO}"
ZAP_MAX_MINUTES="${ZAP_MAX_MINUTES:-30}"

usage() {
    cat <<'HELP_EOF'
Internal Security Assessment v5.0

USAGE
  ./HMTwebscan.sh [OPTIONS] <TARGET_URL>
  TARGET_URL=https://example.com ./HMTwebscan.sh [OPTIONS]

SCAN PROFILES
  fast       Nmap ringan dan pemeriksaan utama dengan waktu lebih singkat.
  standard   Pemeriksaan seimbang untuk audit rutin (default).
  full       Seluruh port TCP, discovery/crawl, dan Nuclei attack-surface.

OPTIONS
  -h, --help                    Tampilkan bantuan ini.
  -V, --version                 Tampilkan versi script.
  -p, --profile PROFILE         fast, standard, atau full.
      --nuclei-profile PROFILE  fast, standard, web, wordpress, atau full.
      --fuzz                    Aktifkan FFUF content discovery.
      --active-zap              Aktifkan ZAP active scan.
      --authorized              Konfirmasi bahwa pengujian telah diizinkan.
      --allow-private           Izinkan target private/localhost/internal.
      --allow-cross-host        Izinkan redirect menuju hostname lain.
      --wordlist FILE           Wordlist khusus untuk FFUF.
      --timeout SECONDS         Batas waktu untuk scanner berat.
      --crawl-depth NUMBER      Kedalaman crawling Katana.

SAFE EXAMPLES
  # Audit standar; ZAP hanya baseline/passive
  ./HMTwebscan.sh https://example.com

  # Pemeriksaan cepat
  ./HMTwebscan.sh --profile fast https://example.com

  # Cakupan penuh; FFUF dan active ZAP tetap tidak aktif
  ./HMTwebscan.sh --profile full https://example.com

  # Full profile dengan FFUF pada target yang telah diizinkan
  ./HMTwebscan.sh --profile full --fuzz --authorized https://example.com

  # Active ZAP pada staging yang telah diizinkan
  ./HMTwebscan.sh --profile full --active-zap --authorized https://staging.example.com

  # Semua fitur agresif
  ./HMTwebscan.sh --profile full --fuzz --active-zap --authorized https://staging.example.com

  # Target internal/private yang telah diizinkan
  ./HMTwebscan.sh --allow-private https://192.168.1.10

ENVIRONMENT VARIABLES
  SCAN_PROFILE=fast|standard|full
  NUCLEI_PROFILE=fast|standard|web|wordpress|full
  ENABLE_SUBDOMAIN=0|1       ENABLE_CRAWL=0|1
  ENABLE_FUZZ=0|1            ENABLE_WPSCAN=0|1
  ENABLE_ACTIVE_ZAP=0|1      I_HAVE_AUTHORIZATION=YES
  ALLOW_PRIVATE_TARGET=0|1   ALLOW_CROSS_HOST_REDIRECTS=0|1
  FUZZ_WORDLIST=/path/file   STEP_TIMEOUT=1800
  HTTP_TIMEOUT=30            MAX_CRAWL_DEPTH=3
  MAX_CRAWL_URLS=5000        MAX_SURFACE_TARGETS=750
  NUCLEI_IMAGE=image:tag     ZAP_IMAGE=image:tag
  ZAP_MAX_MINUTES=30

IMPORTANT
  Jalankan hanya terhadap sistem milik Anda atau sistem yang secara eksplisit
  memberikan izin pengujian. --authorized wajib untuk FFUF dan active ZAP.

REPORT
  Hasil tersimpan di: reports/<domain>_<timestamp>/report.html
HELP_EOF
}

CLI_TARGET=""
while (( $# > 0 )); do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -V|--version) echo "Internal Security Assessment v5.0"; exit 0 ;;
        -p|--profile)
            [[ $# -ge 2 ]] || { echo "[ERROR] $1 membutuhkan nilai." >&2; exit 2; }
            SCAN_PROFILE="$2"; shift 2 ;;
        --nuclei-profile)
            [[ $# -ge 2 ]] || { echo "[ERROR] $1 membutuhkan nilai." >&2; exit 2; }
            NUCLEI_PROFILE="$2"; shift 2 ;;
        --fuzz) ENABLE_FUZZ=1; shift ;;
        --active-zap) ENABLE_ACTIVE_ZAP=1; shift ;;
        --authorized) I_HAVE_AUTHORIZATION=YES; shift ;;
        --allow-private) ALLOW_PRIVATE_TARGET=1; shift ;;
        --allow-cross-host) ALLOW_CROSS_HOST_REDIRECTS=1; shift ;;
        --wordlist)
            [[ $# -ge 2 ]] || { echo "[ERROR] $1 membutuhkan path file." >&2; exit 2; }
            FUZZ_WORDLIST="$2"; shift 2 ;;
        --timeout)
            [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || { echo "[ERROR] --timeout harus berupa detik positif." >&2; exit 2; }
            STEP_TIMEOUT="$2"; shift 2 ;;
        --crawl-depth)
            [[ $# -ge 2 && "$2" =~ ^[1-9][0-9]*$ ]] || { echo "[ERROR] --crawl-depth harus berupa angka positif." >&2; exit 2; }
            MAX_CRAWL_DEPTH="$2"; shift 2 ;;
        --) shift; [[ $# -le 1 ]] || { echo "[ERROR] Terlalu banyak target." >&2; exit 2; }; CLI_TARGET="${1:-}"; shift || true ;;
        -*) echo "[ERROR] Opsi tidak dikenal: $1" >&2; echo "Gunakan --help untuk bantuan." >&2; exit 2 ;;
        *)
            [[ -z "$CLI_TARGET" ]] || { echo "[ERROR] Hanya satu target yang didukung." >&2; exit 2; }
            CLI_TARGET="$1"; shift ;;
    esac
done

if [[ -n "$CLI_TARGET" ]]; then
    TARGET_URL="$CLI_TARGET"
elif [[ -n "${TARGET_URL:-}" ]]; then
    TARGET_URL="$TARGET_URL"
else
    usage >&2
    exit 2
fi

# Normalize URL for consistent scanning.
if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
    TARGET_URL="https://${TARGET_URL}"
fi

# Extract hostname safely (supports ports/path in URL).
readarray -t TARGET_PARTS < <(python3 - "$TARGET_URL" <<'PY2'
from urllib.parse import urlparse
import sys
u = urlparse(sys.argv[1])
print(u.hostname or "")
print(u.port or (443 if u.scheme == 'https' else 80))
print(u.scheme or "")
print(1 if (u.username or u.password) else 0)
PY2
)
TARGET_DOMAIN="${TARGET_PARTS[0]:-}"
TARGET_PORT="${TARGET_PARTS[1]:-}"
TARGET_SCHEME="${TARGET_PARTS[2]:-}"
TARGET_HAS_CREDENTIALS="${TARGET_PARTS[3]:-0}"
if [[ -z "$TARGET_DOMAIN" ]]; then
    echo "[ERROR] Target URL tidak valid: $TARGET_URL"
    exit 1
fi
if [[ "$TARGET_SCHEME" != "http" && "$TARGET_SCHEME" != "https" ]]; then
    echo "[ERROR] Hanya URL http:// atau https:// yang didukung."
    exit 1
fi
if [[ "$TARGET_HAS_CREDENTIALS" == "1" ]]; then
    echo "[ERROR] Jangan menaruh username/password di URL. Gunakan konfigurasi autentikasi terpisah."
    exit 1
fi

# Refuse loopback/private/link-local targets unless explicitly authorized.
if [[ "$ALLOW_PRIVATE_TARGET" != "1" ]]; then
    if ! python3 - "$TARGET_DOMAIN" <<'PY_SCOPE'
import ipaddress, socket, sys
host=sys.argv[1]
try:
    ips={x[4][0] for x in socket.getaddrinfo(host, None)}
except socket.gaierror as e:
    print(f"[ERROR] DNS resolution failed: {e}", file=sys.stderr); raise SystemExit(1)
for raw in ips:
    ip=ipaddress.ip_address(raw.split('%')[0])
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
        print(f"[ERROR] Target resolves to restricted address {ip}. Set ALLOW_PRIVATE_TARGET=1 only for an authorized internal assessment.", file=sys.stderr)
        raise SystemExit(2)
PY_SCOPE
    then
        exit 1
    fi
fi

TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
REPORT_DIR="${REPORT_BASE}/${TARGET_DOMAIN}_${TIMESTAMP}"
mkdir -p "$REPORT_DIR"/{nmap,dns,http,tls,nuclei,zap,subdomains,crawl,fuzz,wpscan,evidence,correlation,meta}
# ZAP's docker image runs as a non-root user (uid 1000) and needs write
# access to the mounted output directory, otherwise zap-report.* never
# gets created. Open permissions on this one subdirectory to avoid that.
chmod 775 "$REPORT_DIR/zap" 2>/dev/null || true

LOG_FILE="$REPORT_DIR/scan.log"
HTML_REPORT="$REPORT_DIR/report.html"
START_TIME="$(date '+%Y-%m-%d %H:%M:%S %Z')"
START_EPOCH="$(date +%s)"
STATUS_FILE="$REPORT_DIR/meta/steps.tsv"
VERSIONS_FILE="$REPORT_DIR/meta/tool-versions.txt"
printf 'step\tstatus\texit_code\tduration_seconds\n' > "$STATUS_FILE"

exec > >(tee -a "$LOG_FILE") 2>&1

echo "============================================================"
echo " Automated Security Testing & Vulnerability Assessment "
echo "============================================================"
echo "Target : $TARGET_URL"
echo "Domain : $TARGET_DOMAIN"
echo "Report : $REPORT_DIR"
echo "Start  : $START_TIME"
echo "============================================================"

have() { command -v "$1" >/dev/null 2>&1; }

is_pd_httpx() {
    have httpx && httpx -h 2>&1 | grep -qiE 'projectdiscovery|technology.*detect|status-code'
}

CURL_REDIRECT_ARGS=()
if [[ "$ALLOW_CROSS_HOST_REDIRECTS" == "1" ]]; then CURL_REDIRECT_ARGS=( -L --max-redirs 10 ); fi
CURL_COMMON_ARGS=( -k -sS --connect-timeout 10 --max-time "$HTTP_TIMEOUT" --proto '=http,https' --proto-redir '=http,https' )

# ---------------------- Docker (Docker-only) -------------------
# Some Parrot/Debian systems have podman-docker installed, where the
# `docker` command actually talks to podman.sock. This assessment must
# use the real Docker Engine only, so resolve a genuine Docker CLI and
# explicitly target the system Docker socket.
DOCKER_BIN=""
for _candidate in "$(command -v docker 2>/dev/null || true)" /usr/bin/docker /usr/local/bin/docker; do
    [[ -n "$_candidate" && -x "$_candidate" ]] || continue
    _resolved="$(readlink -f "$_candidate" 2>/dev/null || echo "$_candidate")"
    case "$_resolved" in
        */podman|*/podman-docker|*/docker-podman*) continue ;;
    esac
    if "$_candidate" --version 2>/dev/null | grep -qiE 'Docker version|Docker Engine'; then
        DOCKER_BIN="$_candidate"
        break
    fi
done

# Force the normal system Docker Engine socket instead of a rootless
# Podman socket/context. Override only if the caller explicitly set it.
# Always use the system Docker Engine socket. Do not inherit a Podman DOCKER_HOST/context.
unset DOCKER_CONTEXT 2>/dev/null || true
DOCKER_HOST="unix:///var/run/docker.sock"
export DOCKER_HOST

have_docker_engine() {
    [[ -n "$DOCKER_BIN" ]] || return 1
    "$DOCKER_BIN" version >/dev/null 2>&1
}

docker_run() {
    "$DOCKER_BIN" run "$@"
}

run_step() {
    local name="$1"; shift
    local started rc duration status
    started="$(date +%s)"
    echo
    echo "------------------------------------------------------------"
    echo "[+] $name"
    echo "------------------------------------------------------------"
    if "$@"; then
        rc=0; status="SUCCESS"; echo "[OK] $name selesai"
    else
        rc=$?
        if [[ "$rc" -eq 124 ]]; then status="TIMEOUT"; else status="FAILED"; fi
        echo "[WARN] $name $status (exit=$rc)"
    fi
    duration=$(( $(date +%s) - started ))
    printf '%s\t%s\t%s\t%s\n' "$name" "$status" "$rc" "$duration" >> "$STATUS_FILE"
    return 0
}

cleanup() {
    local rc=$?
    if [[ "$rc" -ne 0 ]]; then echo "[WARN] Scan dihentikan (exit=$rc). Partial report tetap disimpan di $REPORT_DIR"; fi
}
trap cleanup EXIT
trap 'echo "[WARN] Interrupted"; exit 130' INT TERM

# ------------------------- Dependencies ----------------------
for t in curl nmap openssl dig; do
    if have "$t"; then echo "[OK] $t"; else echo "[WARN] $t tidak ditemukan"; fi
done

{
    echo "assessment_version=5.0"
    echo "bash=$BASH_VERSION"
    for t in curl nmap openssl dig nikto httpx whatweb subfinder dnsx katana ffuf wpscan nuclei testssl.sh; do
        if have "$t"; then
            printf '%s=' "$t"
            "$t" --version 2>&1 | head -n 1 || true
        else
            echo "$t=NOT_INSTALLED"
        fi
    done
    if have_docker_engine; then "$DOCKER_BIN" --version 2>&1 || true; else echo "docker=UNAVAILABLE"; fi
} > "$VERSIONS_FILE"

# Optional/extended scanners. Missing tools are reported and skipped rather than
# making the whole assessment fail.
for t in nikto httpx whatweb subfinder dnsx katana ffuf wpscan testssl.sh; do
    if have "$t"; then echo "[OK] $t"; else echo "[INFO] $t tidak ditemukan (optional)"; fi
done

if have nuclei; then NUCLEI_MODE=host
elif have_docker_engine; then NUCLEI_MODE=docker
else NUCLEI_MODE=none
fi

if have_docker_engine; then ZAP_MODE=docker
else ZAP_MODE=none
fi

case "$SCAN_PROFILE" in
    fast) NMAP_ARGS=( -Pn -sV --version-light --reason -T3 ) ;;
    standard) NMAP_ARGS=( -Pn -sV -sC --reason -T3 ) ;;
    full) NMAP_ARGS=( -Pn -p- -sV -sC --reason -T3 ) ;;
    *) echo "[WARN] SCAN_PROFILE tidak dikenal: $SCAN_PROFILE; memakai standard"; SCAN_PROFILE=standard; NMAP_ARGS=( -Pn -sV -sC --reason -T3 ) ;;
esac

# ----------------------------- DNS ---------------------------
step_dns() {
    {
        echo "=== A ==="; dig A "$TARGET_DOMAIN" +noall +answer
        echo; echo "=== AAAA ==="; dig AAAA "$TARGET_DOMAIN" +noall +answer
        echo; echo "=== MX ==="; dig MX "$TARGET_DOMAIN" +noall +answer
        echo; echo "=== NS ==="; dig NS "$TARGET_DOMAIN" +noall +answer
        echo; echo "=== TXT ==="; dig TXT "$TARGET_DOMAIN" +noall +answer
        echo; echo "=== CNAME ==="; dig CNAME "$TARGET_DOMAIN" +noall +answer
        echo; echo "=== SOA ==="; dig SOA "$TARGET_DOMAIN" +noall +answer
        echo; echo "=== DNSSEC ==="; dig DNSKEY "$TARGET_DOMAIN" +dnssec +noall +answer
    } > "$REPORT_DIR/dns/dns-recon.txt" 2>&1
}
run_step "DNS Recon" step_dns

# ----------------------------- Nmap --------------------------
step_nmap() {
    timeout --foreground "$STEP_TIMEOUT" nmap "${NMAP_ARGS[@]}" "$TARGET_DOMAIN" \
        -oA "$REPORT_DIR/nmap/nmap" \
        > "$REPORT_DIR/nmap/nmap-console.txt" 2>&1
    if nmap --script-help vulners >/dev/null 2>&1; then
        timeout --foreground "$STEP_TIMEOUT" nmap -Pn -sV --script vulners "$TARGET_DOMAIN" \
            -oN "$REPORT_DIR/nmap/nmap-vulners.txt" \
            >> "$REPORT_DIR/nmap/nmap-console.txt" 2>&1 || true
    else
        echo "Nmap NSE vulners script tidak tersedia." > "$REPORT_DIR/nmap/nmap-vulners.txt"
    fi
}
run_step "Nmap Service Scan" step_nmap

# ----------------------------- HTTP --------------------------
step_http() {
    {
        echo "=== HEADERS ==="
        curl "${CURL_COMMON_ARGS[@]}" "${CURL_REDIRECT_ARGS[@]}" -I "$TARGET_URL" || return 1
        echo; echo "=== RESPONSE ==="
        curl "${CURL_COMMON_ARGS[@]}" "${CURL_REDIRECT_ARGS[@]}" -o /dev/null -w "
HTTP Code      : %{http_code}
Content Type   : %{content_type}
HTTP Version   : %{http_version}
Remote IP      : %{remote_ip}
SSL Verify     : %{ssl_verify_result}
Connect Time   : %{time_connect}
TTFB           : %{time_starttransfer}
Total Time     : %{time_total}
" "$TARGET_URL" || return 1
        echo; echo "=== OPTIONS ==="
        curl "${CURL_COMMON_ARGS[@]}" -i -X OPTIONS "$TARGET_URL" || true
        echo; echo "=== SECURITY HEADERS ==="
        curl "${CURL_COMMON_ARGS[@]}" "${CURL_REDIRECT_ARGS[@]}" -I "$TARGET_URL" |
            grep -Ei "strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|cross-origin|set-cookie" || true
    } > "$REPORT_DIR/http/http-recon.txt" 2>&1
}
run_step "HTTP Recon" step_http


# ------------------------ Extended HTTP ------------------------
step_nikto() {
    if ! have nikto; then echo "Nikto tidak tersedia." > "$REPORT_DIR/http/nikto.txt"; return 1; fi
    nikto -h "$TARGET_URL" -nointeractive -output "$REPORT_DIR/http/nikto.txt" 2>&1 || true
    return 0
}
run_step "Nikto Web Server Scan" step_nikto

step_httpx() {
    if ! is_pd_httpx; then echo "ProjectDiscovery httpx tidak tersedia (binary lain bernama httpx diabaikan)." > "$REPORT_DIR/http/httpx.txt"; return 1; fi
    printf '%s\n' "$TARGET_URL" | httpx -silent -status-code -title -tech-detect -server -ip -location -web-server -response-time -tls-grab -json > "$REPORT_DIR/http/httpx.json" 2>&1 || true
    if [[ ! -s "$REPORT_DIR/http/httpx.json" ]]; then
        printf '%s\n' "$TARGET_URL" | httpx -silent -status-code -title -tech-detect -server -ip -location -web-server -response-time > "$REPORT_DIR/http/httpx.txt" 2>&1 || true
    else
        python3 - "$REPORT_DIR/http/httpx.json" "$REPORT_DIR/http/httpx.txt" <<'PYHTTPX'
import sys, json
src,dst=sys.argv[1:]
out=[]
for line in open(src, errors='ignore'):
    try:
        d=json.loads(line)
        out.append(f"URL: {d.get('url','')}\nStatus: {d.get('status_code','')}\nTitle: {d.get('title','')}\nServer: {d.get('webserver',d.get('server',''))}\nIP: {d.get('host','')}\nTech: {', '.join(d.get('tech',[]) or [])}\nResponse time: {d.get('response_time','')}\n")
    except Exception: pass
open(dst,'w').write('\n'.join(out) or 'No httpx JSON records.\n')
PYHTTPX
    fi
    return 0
}
run_step "HTTPX Fingerprinting" step_httpx

step_whatweb() {
    if ! have whatweb; then echo "WhatWeb tidak tersedia." > "$REPORT_DIR/http/whatweb.txt"; return 1; fi
    whatweb --color=never --log-brief="$REPORT_DIR/http/whatweb.txt" "$TARGET_URL" >/dev/null 2>&1 || whatweb --color=never "$TARGET_URL" > "$REPORT_DIR/http/whatweb.txt" 2>&1 || true
    return 0
}
run_step "WhatWeb Technology Fingerprinting" step_whatweb

step_waf() {
    {
        echo "=== WAF / CDN HEURISTIC DETECTION ==="
        headers="$(curl "${CURL_COMMON_ARGS[@]}" "${CURL_REDIRECT_ARGS[@]}" -I "$TARGET_URL" 2>/dev/null || true)"
        echo "$headers"
        echo
        echo "=== Indicators ==="
        if echo "$headers" | grep -qiE 'cloudflare|cf-ray|cf-cache-status'; then echo "Cloudflare: DETECTED"; fi
        if echo "$headers" | grep -qiE 'x-sucuri|sucuri'; then echo "Sucuri: DETECTED"; fi
        if echo "$headers" | grep -qiE 'x-akamai|akamai'; then echo "Akamai: DETECTED"; fi
        if echo "$headers" | grep -qiE 'x-cdn|cdn'; then echo "Generic CDN header indicator: DETECTED"; fi
        if ! echo "$headers" | grep -qiE 'cloudflare|cf-ray|cf-cache-status|x-sucuri|sucuri|x-akamai|akamai|x-cdn|cdn'; then echo "WAF/CDN: NOT CONFIRMED BY HEADER HEURISTICS"; fi
    } > "$REPORT_DIR/http/waf.txt"
}
run_step "WAF/CDN Heuristic Detection" step_waf

step_testssl() {
    local bin=""
    if have testssl.sh; then bin="$(command -v testssl.sh)"; elif [[ -x "$SCRIPT_DIR/testssl.sh" ]]; then bin="$SCRIPT_DIR/testssl.sh"; fi
    if [[ -z "$bin" ]]; then echo "testssl.sh tidak tersedia." > "$REPORT_DIR/tls/testssl.txt"; return 1; fi
    "$bin" --quiet --color 0 "$TARGET_DOMAIN:$TARGET_PORT" > "$REPORT_DIR/tls/testssl.txt" 2>&1
}
run_step "testssl.sh TLS Assessment" step_testssl

# ------------------------------ TLS --------------------------
step_tls() {
    {
        echo "=== CERTIFICATE ==="
        echo | openssl s_client -connect "${TARGET_DOMAIN}:${TARGET_PORT}" -servername "$TARGET_DOMAIN" 2>/dev/null |
            openssl x509 -noout -subject -issuer -serial -dates -fingerprint -ext subjectAltName || true
        echo; echo "=== TLS 1.2 ==="
        timeout 12 openssl s_client -brief -connect "${TARGET_DOMAIN}:${TARGET_PORT}" -tls1_2 -servername "$TARGET_DOMAIN" </dev/null 2>&1 || true
        echo; echo "=== TLS 1.3 ==="
        timeout 12 openssl s_client -brief -connect "${TARGET_DOMAIN}:${TARGET_PORT}" -tls1_3 -servername "$TARGET_DOMAIN" </dev/null 2>&1 || true
    } > "$REPORT_DIR/tls/tls-recon.txt" 2>&1
}
run_step "TLS Recon" step_tls

# ----------------------------- Nuclei ------------------------
step_nuclei() {
    local nuclei_extra=()
    case "$NUCLEI_PROFILE" in
        fast) nuclei_extra=( -severity high,critical -rate-limit 15 -bulk-size 10 -concurrency 5 ) ;;
        standard) nuclei_extra=( -severity info,low,medium,high,critical -rate-limit 10 -bulk-size 10 -concurrency 5 ) ;;
        web) nuclei_extra=( -severity low,medium,high,critical -tags exposure,misconfig,cve,tech -rate-limit 10 -bulk-size 10 -concurrency 5 ) ;;
        wordpress) nuclei_extra=( -severity low,medium,high,critical -tags wordpress,cve,exposure,misconfig -rate-limit 8 -bulk-size 10 -concurrency 4 ) ;;
        full) nuclei_extra=( -severity info,low,medium,high,critical -rate-limit 10 -bulk-size 10 -concurrency 5 ) ;;
        *) echo "[WARN] NUCLEI_PROFILE tidak dikenal: $NUCLEI_PROFILE; memakai standard"; NUCLEI_PROFILE=standard; nuclei_extra=( -severity info,low,medium,high,critical -rate-limit 10 -bulk-size 10 -concurrency 5 ) ;;
    esac
    case "$NUCLEI_MODE" in
        host)
            local scope_args=( -fhr )
            [[ "$ALLOW_PRIVATE_TARGET" == "1" ]] || scope_args+=( -lna )
            timeout --foreground "$STEP_TIMEOUT" nuclei -u "$TARGET_URL" \
                "${nuclei_extra[@]}" \
                "${scope_args[@]}" -no-stdin -duc \
                -jsonl-export "$REPORT_DIR/nuclei/nuclei.json" \
                -o "$REPORT_DIR/nuclei/nuclei.txt"
            ;;
        docker)
            docker_run --rm \
                -v "$(realpath "$REPORT_DIR/nuclei"):/output" \
                "$NUCLEI_IMAGE" \
                -u "$TARGET_URL" \
                "${nuclei_extra[@]}" \
                -fhr -no-stdin -duc \
                -jsonl-export /output/nuclei.json \
                -o /output/nuclei.txt
            ;;
        *)
            echo "Nuclei tidak tersedia." > "$REPORT_DIR/nuclei/nuclei.txt"
            return 1
            ;;
    esac
}
run_step "Nuclei" step_nuclei

# ---------------------- Attack Surface Discovery ----------------
step_subdomains() {
    if [[ "$ENABLE_SUBDOMAIN" != "1" ]]; then echo "Subdomain discovery disabled." > "$REPORT_DIR/subdomains/subfinder.txt"; return 0; fi
    if ! have subfinder; then echo "subfinder tidak tersedia." > "$REPORT_DIR/subdomains/subfinder.txt"; return 1; fi
    subfinder -silent -d "$TARGET_DOMAIN" -o "$REPORT_DIR/subdomains/subfinder.txt" 2>&1 || true
    # Defensive filtering: only the target itself and direct/child subdomains remain in scope.
    python3 - "$TARGET_DOMAIN" "$REPORT_DIR/subdomains/subfinder.txt" <<'PY_SUBS'
import sys
from pathlib import Path
root=sys.argv[1].lower().rstrip('.')
p=Path(sys.argv[2])
if p.exists():
    valid=sorted({x.strip().lower().rstrip('.') for x in p.read_text(errors='ignore').splitlines() if x.strip().lower().rstrip('.') == root or x.strip().lower().rstrip('.').endswith('.'+root)})
    p.write_text('\n'.join(valid)+('\n' if valid else ''))
PY_SUBS
    if have dnsx && [[ -s "$REPORT_DIR/subdomains/subfinder.txt" ]]; then
        dnsx -silent -l "$REPORT_DIR/subdomains/subfinder.txt" -a -resp -o "$REPORT_DIR/subdomains/dnsx.txt" 2>&1 || true
    else
        echo "dnsx tidak tersedia atau tidak ada subdomain." > "$REPORT_DIR/subdomains/dnsx.txt"
    fi
    if is_pd_httpx && [[ -s "$REPORT_DIR/subdomains/subfinder.txt" ]]; then
        httpx -silent -l "$REPORT_DIR/subdomains/subfinder.txt" -status-code -title -tech-detect -json -o "$REPORT_DIR/subdomains/live-http.json" 2>"$REPORT_DIR/subdomains/httpx-errors.txt" || true
        python3 - "$REPORT_DIR/subdomains/live-http.json" "$REPORT_DIR/subdomains/live-urls.txt" <<'PY_LIVE'
import json,sys
urls=[]
try:
    for line in open(sys.argv[1],errors='ignore'):
        try:
            d=json.loads(line); u=d.get('url') or d.get('input')
            if u: urls.append(u)
        except Exception: pass
except FileNotFoundError: pass
open(sys.argv[2],'w').write('\n'.join(sorted(set(urls)))+('\n' if urls else ''))
PY_LIVE
    fi
    return 0
}
run_step "Subfinder + DNSX Attack Surface Discovery" step_subdomains

step_crawl() {
    if [[ "$ENABLE_CRAWL" != "1" ]]; then echo "Crawling disabled." > "$REPORT_DIR/crawl/urls.txt"; return 0; fi
    if ! have katana; then echo "katana tidak tersedia." > "$REPORT_DIR/crawl/urls.txt"; return 1; fi
    katana -u "$TARGET_URL" -silent -d "$MAX_CRAWL_DEPTH" -fs fqdn -jc -kf all -o "$REPORT_DIR/crawl/urls.raw.txt" 2>"$REPORT_DIR/crawl/katana-errors.txt" || true
    python3 - "$TARGET_DOMAIN" "$MAX_CRAWL_URLS" "$REPORT_DIR/crawl/urls.raw.txt" "$REPORT_DIR/crawl/urls.txt" <<'PY_URLS'
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
root=sys.argv[1].lower(); limit=int(sys.argv[2]); src=Path(sys.argv[3]); dst=Path(sys.argv[4]); out=[]; seen=set()
if src.exists():
    for raw in src.read_text(errors='ignore').splitlines():
        try:
            u=urlsplit(raw.strip()); host=(u.hostname or '').lower()
            if host != root and not host.endswith('.'+root): continue
            clean=urlunsplit((u.scheme,u.netloc,u.path,u.query,''))
            if clean not in seen: seen.add(clean); out.append(clean)
            if len(out)>=limit: break
        except Exception: pass
dst.write_text('\n'.join(out)+('\n' if out else ''))
PY_URLS
    return 0
}
run_step "Katana Web Crawling" step_crawl

step_surface_targets() {
    python3 - "$TARGET_URL" "$MAX_SURFACE_TARGETS" "$REPORT_DIR/subdomains/live-urls.txt" "$REPORT_DIR/crawl/urls.txt" "$REPORT_DIR/nuclei/surface-targets.txt" <<'PY_SURFACE'
import sys
from pathlib import Path
root=sys.argv[1]; limit=int(sys.argv[2]); out=[]; seen=set()
for u in [root]:
    if u not in seen: seen.add(u); out.append(u)
for name in sys.argv[3:5]:
    p=Path(name)
    if not p.exists(): continue
    for u in p.read_text(errors='ignore').splitlines():
        u=u.strip()
        if u and u not in seen: seen.add(u); out.append(u)
        if len(out)>=limit: break
    if len(out)>=limit: break
Path(sys.argv[5]).write_text('\n'.join(out)+'\n')
PY_SURFACE
}
run_step "Build In-Scope Surface Targets" step_surface_targets

step_nuclei_surface() {
    [[ -s "$REPORT_DIR/nuclei/surface-targets.txt" ]] || return 0
    if [[ "$NUCLEI_MODE" != "host" ]]; then
        echo "Surface Nuclei requires host nuclei; root target was already scanned." > "$REPORT_DIR/nuclei/surface-note.txt"
        return 0
    fi
    local extra=( -severity low,medium,high,critical -rate-limit 8 -bulk-size 5 -concurrency 4 )
    local scope=( -fhr )
    [[ "$ALLOW_PRIVATE_TARGET" == "1" ]] || scope+=( -lna )
    timeout --foreground "$STEP_TIMEOUT" nuclei -l "$REPORT_DIR/nuclei/surface-targets.txt" "${extra[@]}" "${scope[@]}" -no-stdin -duc \
        -jsonl-export "$REPORT_DIR/nuclei/nuclei-surface.json" -o "$REPORT_DIR/nuclei/nuclei-surface.txt"
}
if [[ "$SCAN_PROFILE" == "full" ]]; then run_step "Nuclei In-Scope Surface Scan" step_nuclei_surface; fi

step_fuzz() {
    if [[ "$ENABLE_FUZZ" != "1" ]]; then echo "FFUF disabled (set ENABLE_FUZZ=1 to enable)." > "$REPORT_DIR/fuzz/ffuf.txt"; return 0; fi
    if ! have ffuf; then echo "ffuf tidak tersedia." > "$REPORT_DIR/fuzz/ffuf.txt"; return 1; fi
    if [[ "$I_HAVE_AUTHORIZATION" != "YES" ]]; then echo "FFUF membutuhkan I_HAVE_AUTHORIZATION=YES." > "$REPORT_DIR/fuzz/ffuf.txt"; return 1; fi
    local wl="$FUZZ_WORDLIST"
    if [[ -z "$wl" ]]; then
        for candidate in /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/wordlists/dirb/common.txt /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt; do
            if [[ -f "$candidate" ]]; then wl="$candidate"; break; fi
        done
    fi
    if [[ -z "$wl" ]]; then echo "Tidak menemukan wordlist. Set FUZZ_WORDLIST=/path/to/wordlist." > "$REPORT_DIR/fuzz/ffuf.txt"; return 1; fi
    timeout --foreground "$STEP_TIMEOUT" ffuf -u "${TARGET_URL%/}/FUZZ" -w "$wl" -ac -mc all -rate 10 -t 10 -of json -o "$REPORT_DIR/fuzz/ffuf.json" > "$REPORT_DIR/fuzz/ffuf.txt" 2>&1
}
run_step "FFUF Content Discovery" step_fuzz

step_wpscan() {
    if [[ "$ENABLE_WPSCAN" != "1" ]]; then echo "WPScan disabled." > "$REPORT_DIR/wpscan/wpscan.txt"; return 0; fi
    if ! have wpscan; then echo "WPScan tidak tersedia." > "$REPORT_DIR/wpscan/wpscan.txt"; return 1; fi
    # Only run when WordPress is detected by the page/headers/body heuristics.
    local body="$(curl "${CURL_COMMON_ARGS[@]}" "${CURL_REDIRECT_ARGS[@]}" "$TARGET_URL" 2>/dev/null || true)"
    if ! echo "$body" | grep -qiE 'wp-content|wp-includes|wordpress'; then
        echo "WordPress tidak terdeteksi; WPScan dilewati." > "$REPORT_DIR/wpscan/wpscan.txt"
        return 0
    fi
    timeout --foreground "$STEP_TIMEOUT" wpscan --url "$TARGET_URL" --enumerate vp,vt,cb --format json --output "$REPORT_DIR/wpscan/wpscan.json" --no-update > "$REPORT_DIR/wpscan/wpscan.txt" 2>&1
}
run_step "WordPress WPScan Assessment" step_wpscan

# ------------------------------- ZAP -------------------------
step_zap() {
    case "$ZAP_MODE" in
        docker)
            # Docker-only. Do not use docker info here: on some Docker CLI setups
            # (especially when contexts/plugins are present) docker info can fail
            # even though docker run works correctly. The actual docker run below
            # is the authoritative connectivity test.
            if ! have_docker_engine; then
                {
                    echo "Docker Engine tidak dapat diakses."
                    echo "Docker CLI : ${DOCKER_BIN:-tidak ditemukan}"
                    echo "DOCKER_HOST: $DOCKER_HOST"
                    echo
                    echo "Pastikan Docker Engine aktif dan /var/run/docker.sock dapat diakses user ini."
                } > "$REPORT_DIR/zap/zap-error.txt"
                return 1
            fi

            # Remove stale ZAP Automation Framework files/reports from previous runs.
            rm -f "$REPORT_DIR/zap/zap.yaml" \
                  "$REPORT_DIR/zap/zap-report.html" \
                  "$REPORT_DIR/zap/zap-report.json" \
                  "$REPORT_DIR/zap/zap-report.md" 2>/dev/null || true

            # ZAP runs as a non-root container user. Ensure the mounted directory is writable.
            chmod 775 "$REPORT_DIR/zap" 2>/dev/null || true

            # No "-t" here: docker run's pseudo-TTY allocation breaks when
            # stdout has already been redirected through the tee pipe above
            # (see `exec > >(tee -a ...)` earlier). zap-baseline.py doesn't
            # need a TTY to run non-interactively.
            local zap_script="zap-baseline.py"
            if [[ "$ENABLE_ACTIVE_ZAP" == "1" ]]; then
                if [[ "$I_HAVE_AUTHORIZATION" != "YES" ]]; then
                    echo "Active ZAP membutuhkan I_HAVE_AUTHORIZATION=YES." > "$REPORT_DIR/zap/zap-error.txt"
                    return 1
                fi
                zap_script="zap-full-scan.py"
            fi
            docker_run --rm \
                -v "$(realpath "$REPORT_DIR/zap"):/zap/wrk:rw" \
                "$ZAP_IMAGE" \
                "$zap_script" -t "$TARGET_URL" \
                -T "$ZAP_MAX_MINUTES" \
                -r zap-report.html -J zap-report.json -w zap-report.md
            local rc=$?
            # zap-baseline.py returns non-zero when it finds WARN/FAIL
            # alerts (by design) - that's not a script failure, only
            # missing report files are.
            if [[ -f "$REPORT_DIR/zap/zap-report.html" || -f "$REPORT_DIR/zap/zap-report.json" ]]; then
                return 0
            fi
            return "$rc"
            ;;
        *)
            echo "Docker tidak tersedia." > "$REPORT_DIR/zap/zap-error.txt"
            return 1
            ;;
    esac
}
if [[ "$ENABLE_ACTIVE_ZAP" == "1" ]]; then
    run_step "OWASP ZAP Active Scan" step_zap
else
    run_step "OWASP ZAP Baseline" step_zap
fi


# -------------------------- Correlation -------------------------
step_correlation() {
    python3 - "$REPORT_DIR" "$TARGET_URL" <<'PYCORR'
import sys, json, re
from pathlib import Path
from urllib.parse import urlparse

report=Path(sys.argv[1]); target_url=sys.argv[2]; out=report/'correlation'; out.mkdir(exist_ok=True)
findings=[]

SEV=['critical','high','medium','low','info']
WEIGHT={'critical':25,'high':15,'medium':7,'low':2,'info':0}
CONF_WEIGHT={'high':1.0,'medium':0.75,'low':0.5}

def norm(s):
    s=str(s or '').lower()
    aliases={
        'content security policy':'csp','content-security-policy':'csp','csp header not set':'csp',
        'x content type options':'x-content-type-options','x-content-type-options header missing':'x-content-type-options',
        'strict transport security':'hsts','strict-transport-security':'hsts',
        'referrer policy':'referrer-policy','permissions policy':'permissions-policy',
        'anti clickjacking':'clickjacking','x-frame-options':'clickjacking','frame ancestors':'clickjacking',
        'sub resource integrity':'sri','subresource integrity':'sri','sri attribute missing':'sri',
        'cookie without samesite':'cookie-samesite','missing-cookie-samesite':'cookie-samesite',
    }
    for a,b in aliases.items(): s=s.replace(a,b)
    return re.sub(r'[^a-z0-9]+',' ',s).strip()

def add(source,severity,name,evidence='',url='',confidence='medium',solution='',reference='',cve=''):
    sev=str(severity or 'info').lower()
    if sev in ('informational','information','notice'): sev='info'
    if sev not in SEV: sev='info'
    findings.append({
        'source':source,'severity':sev,'name':str(name or '').strip() or 'Unnamed finding',
        'evidence':str(evidence or '').strip(),'url':str(url or '').strip(),
        'confidence':confidence if confidence in CONF_WEIGHT else 'medium',
        'solution':str(solution or '').strip(),'reference':reference,'cve':cve
    })

# Nuclei JSONL (root target + optional in-scope surface scan)
for nf in (report/'nuclei/nuclei.json', report/'nuclei/nuclei-surface.json'):
  if nf.exists():
    for line in nf.read_text(errors='ignore').splitlines():
        try:
            d=json.loads(line); i=d.get('info',{}); sev=str(i.get('severity','info')).lower()
            add('Nuclei',sev,i.get('name',d.get('template-id','')),d.get('matched-at',d.get('host','')),d.get('matched-at',''),'high',i.get('description',''),' '.join(map(str,i.get('reference',[]) if isinstance(i.get('reference',[]),list) else [i.get('reference','')])),d.get('template-id',''))
        except Exception: pass

# ZAP JSON
zf=report/'zap/zap-report.json'
if zf.exists():
    try:
        data=json.loads(zf.read_text(errors='ignore')); sites=data.get('site',[]); sites=[sites] if isinstance(sites,dict) else sites
        for site in sites:
            for a in site.get('alerts',[]):
                r=str(a.get('riskdesc',a.get('riskcode','Info'))).split()[0].lower()
                if r == 'informational': r='info'
                instances=a.get('instances') or [{}]
                for inst in instances[:50]:
                    evidence=' | '.join(str(x) for x in (inst.get('method',''),inst.get('uri',''),inst.get('param',''),inst.get('evidence','')) if x)
                    add('ZAP',r,a.get('name',''),evidence,inst.get('uri',site.get('@name','')),'high',a.get('solution',''),a.get('reference',''),a.get('cweid',''))
    except Exception: pass

# Nikto: only convert security-relevant observations, not every informational banner.
nk=report/'http/nikto.txt'
if nk.exists():
    for line in nk.read_text(errors='ignore').splitlines():
        if not line.startswith('+ '): continue
        text=line[2:].strip(); low=text.lower()
        if any(x in low for x in ('suggested security header missing','x-content-type-options header is not set')):
            sev='low'
            if 'content-security-policy' in low: sev='low'
            if 'strict-transport-security' in low: sev='low'
            name=re.sub(r'^\[[^]]+\]\s*','',text).split(':',1)[-1].strip()
            add('Nikto',sev,name,text,target_url,'medium','Review and implement the header where the hosting/platform permits it.')
        elif 'server leaks' in low or 'outdated' in low or 'interesting' in low or 'allowed http methods' in low:
            add('Nikto','low',re.sub(r'^\[[^]]+\]\s*','',text),text,target_url,'medium','Review the Nikto observation and validate manually.')
        elif 'cve-' in low or 'osvdb-' in low:
            m=re.search(r'(CVE-\d{4}-\d{4,7})',text,re.I)
            add('Nikto','medium',text,text,target_url,'medium','Validate the affected component/version and apply the vendor fix if confirmed.',cve=m.group(1).upper() if m else '')

# testssl.sh: capture explicit warnings/failures, not normal PASS output.
ts=report/'tls/testssl.txt'
if ts.exists():
    for line in ts.read_text(errors='ignore').splitlines():
        low=line.lower()
        if any(tok in low for tok in ('vulnerable','not ok','fail','deprecated','weak')) and not re.search(r'\b(pass|ok)\b',low):
            add('testssl.sh','medium',line.strip(),line.strip(),target_url,'medium','Review the testssl.sh result and apply the recommended TLS configuration change.')

# WPScan JSON: vulnerabilities can be nested under core, plugins and themes.
wf=report/'wpscan/wpscan.json'
if wf.exists():
    try:
        d=json.loads(wf.read_text(errors='ignore'))
        vulns=[]
        def collect(obj, component='WordPress'):
            if isinstance(obj,dict):
                for v in obj.get('vulnerabilities',[]) or []:
                    if isinstance(v,dict): vulns.append((component,v))
                for k,v in obj.items():
                    if k!='vulnerabilities': collect(v, str(obj.get('slug') or obj.get('name') or k))
            elif isinstance(obj,list):
                for v in obj: collect(v,component)
        collect(d)
        for component,v in vulns:
            sev='medium'
            refs=v.get('references',{}) or {}
            title=f"{component}: {v.get('title','WordPress vulnerability')}"
            cvss=(v.get('cvss') or {})
            score=cvss.get('score') if isinstance(cvss,dict) else None
            try:
                if score is not None:
                    x=float(score); sev='critical' if x>=9 else 'high' if x>=7 else 'medium' if x>=4 else 'low'
            except Exception: pass
            add('WPScan',sev,title,json.dumps(v,ensure_ascii=False),target_url,'high',v.get('fixed_in','Review vendor/plugin/theme advisory.'),json.dumps(refs,ensure_ascii=False))
    except Exception: pass

# Nmap vulners text: CVE lines are candidate findings and require validation.
nv=report/'nmap/nmap-vulners.txt'
if nv.exists():
    for line in nv.read_text(errors='ignore').splitlines():
        m=re.search(r'(CVE-\d{4}-\d{4,7})',line,re.I)
        if not m: continue
        score=None
        sm=re.search(r'\b([0-9]\.[0-9])\b',line)
        try: score=float(sm.group(1)) if sm else None
        except Exception: score=None
        sev='medium' if score is None else ('critical' if score>=9 else 'high' if score>=7 else 'medium' if score>=4 else 'low')
        add('Nmap-vulners',sev,m.group(1).upper(),line,target_url,'low','Validate service/version exposure before treating this CVE as confirmed.',cve=m.group(1).upper())

# FFUF: discovery evidence is informational unless explicitly tied to a vulnerability.
ff=report/'fuzz/ffuf.json'
if ff.exists():
    try:
        d=json.loads(ff.read_text(errors='ignore'))
        results=d.get('results',[]) if isinstance(d,dict) else []
        for r in results[:100]:
            url=r.get('url',''); status=r.get('status',0)
            if url:
                add('FFUF','info','Content Discovery',f'{status} {url}',url,'high','Review discovered paths for unintended exposure; do not treat discovery alone as a vulnerability.')
    except Exception: pass

# Deduplicate using normalized issue category + target path, while preserving all sources.
groups={}
for f in findings:
    base=norm(f['name'])
    # Common header findings should collapse even when scanners use different names.
    for token in ('csp','hsts','x-content-type-options','referrer-policy','permissions-policy','clickjacking','sri','cookie-samesite'):
        if token in base: base=token; break
    path=''
    try: path=urlparse(f.get('url') or f.get('evidence') or '').path
    except Exception: path=''
    key=(base,path)
    groups.setdefault(key,[]).append(f)

merged=[]
for key,items in groups.items():
    # SEV is ordered from most to least severe, therefore min() preserves
    # the highest severity observed across scanners.
    best=min(items,key=lambda x: SEV.index(x['severity']))
    best=dict(best)
    sources=sorted(set(x['source'] for x in items))
    best['sources']=sources
    best['count']=len(items)
    best['confidence']='high' if len(sources)>=2 else best.get('confidence','medium')
    best['evidence_all']=sorted(set(x['evidence'] for x in items if x.get('evidence')))
    best['references_all']=sorted(set(str(x.get('reference','')) for x in items if x.get('reference')))
    merged.append(best)

merged.sort(key=lambda x:(SEV.index(x['severity']),norm(x['name'])))

# Scanner inventory for dashboard.
scanner_files={
 'Nmap':'nmap/nmap.xml','DNS':'dns/dns-recon.txt','HTTP':'http/http-recon.txt','Nikto':'http/nikto.txt',
 'HTTPX':'http/httpx.json','WhatWeb':'http/whatweb.txt','WAF/CDN':'http/waf.txt','testssl.sh':'tls/testssl.txt',
 'Subfinder':'subdomains/subfinder.txt','DNSX':'subdomains/dnsx.txt','Katana':'crawl/urls.txt','FFUF':'fuzz/ffuf.json',
 'WPScan':'wpscan/wpscan.json','Nuclei':'nuclei/nuclei.json','ZAP':'zap/zap-report.json'
}
scanner_status={k:(report/v).exists() and (report/v).stat().st_size>0 for k,v in scanner_files.items()}
step_status={}
sf=report/'meta/steps.tsv'
if sf.exists():
    for line in sf.read_text(errors='ignore').splitlines()[1:]:
        parts=line.split('\t')
        if len(parts)>=4: step_status[parts[0]]={'status':parts[1],'exit_code':parts[2],'duration_seconds':parts[3]}
step_map={
 'Nmap':'Nmap Service Scan','DNS':'DNS Recon','HTTP':'HTTP Recon','Nikto':'Nikto Web Server Scan',
 'HTTPX':'HTTPX Fingerprinting','WhatWeb':'WhatWeb Technology Fingerprinting','WAF/CDN':'WAF/CDN Heuristic Detection',
 'testssl.sh':'testssl.sh TLS Assessment','Subfinder':'Subfinder + DNSX Attack Surface Discovery',
 'DNSX':'Subfinder + DNSX Attack Surface Discovery','Katana':'Katana Web Crawling','FFUF':'FFUF Content Discovery',
 'WPScan':'WordPress WPScan Assessment','Nuclei':'Nuclei',
 'ZAP':('OWASP ZAP Active Scan' if 'OWASP ZAP Active Scan' in step_status else 'OWASP ZAP Baseline')
}
for scanner,step in step_map.items():
    if step in step_status and step_status[step]['status'] != 'SUCCESS': scanner_status[scanner]=False

json.dump({'version':'5.0','findings':merged,'raw_count':len(findings),'deduplicated_count':len(merged),'scanner_status':scanner_status,'step_status':step_status},open(out/'findings.json','w'),indent=2,ensure_ascii=False)
with open(out/'findings.txt','w',encoding='utf-8') as fh:
    for f in merged:
        fh.write(f"[{f['severity'].upper()}] {f['name']} | sources={','.join(f['sources'])} | confidence={f['confidence']} | {f['evidence']}\n")
print(f"[OK] Correlated findings: {len(merged)} (raw: {len(findings)})")
PYCORR
}
run_step "Finding Correlation & Deduplication" step_correlation

# -------------------------- Data parsing ---------------------
END_TIME="$(date '+%Y-%m-%d %H:%M:%S %Z')"
DURATION_SECONDS=$(( $(date +%s) - START_EPOCH ))
python3 - "$REPORT_DIR" "$TARGET_DOMAIN" "$TARGET_URL" "$START_TIME" "$HTML_REPORT" "$SCAN_PROFILE" "$NUCLEI_PROFILE" "$END_TIME" "$DURATION_SECONDS" <<'PY'
import sys, json, html, re, os
from pathlib import Path
from xml.etree import ElementTree as ET

report = Path(sys.argv[1])
domain, url, start, output, scan_profile, nuclei_profile, end_time, duration_seconds = sys.argv[2:]

def esc(x): return html.escape(str(x or ""))

# Nmap
ports = []
nmap_file = report / "nmap/nmap.xml"
if nmap_file.exists():
    try:
        root = ET.parse(nmap_file).getroot()
        for p in root.findall(".//port"):
            state = p.find("state")
            if state is not None and state.get("state") == "open":
                svc = p.find("service")
                ports.append({
                    "port": p.get("portid", ""),
                    "proto": p.get("protocol", ""),
                    "service": svc.get("name", "") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                })
    except Exception:
        pass

# Nuclei JSONL
nuclei = []
for nf in (report / "nuclei/nuclei.json", report / "nuclei/nuclei-surface.json"):
 if nf.exists():
    for line in nf.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            info = d.get("info", {})
            sev = str(info.get("severity", "info")).lower()
            nuclei.append({
                "severity": sev,
                "name": info.get("name", d.get("template-id", "")),
                "template": d.get("template-id", ""),
                "matched": d.get("matched-at", d.get("host", "")),
                "description": info.get("description", ""),
                "reference": info.get("reference", []),
            })
        except Exception:
            pass

# ZAP JSON (best-effort across common ZAP report shapes)
zap = []
zf = report / "zap/zap-report.json"
if zf.exists():
    try:
        data = json.loads(zf.read_text(errors="ignore"))
        sites = data.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]
        for site in sites:
            alerts = site.get("alerts", []) if isinstance(site, dict) else []
            for a in alerts:
                risk = a.get("riskdesc", a.get("riskcode", "Info"))
                sev = str(risk).split()[0].lower()
                if sev not in ("critical", "high", "medium", "low", "informational", "info"):
                    sev = "info"
                zap.append({
                    "severity": sev,
                    "name": a.get("name", ""),
                    "url": a.get("url", site.get("@name", "") if isinstance(site, dict) else ""),
                    "desc": a.get("desc", ""),
                    "solution": a.get("solution", ""),
                    "cwe": a.get("cweid", ""),
                    "wasc": a.get("wascid", ""),
                })
    except Exception:
        pass

# Correlated/deduplicated findings
correlated=[]
cf=report / "correlation/findings.json"
if cf.exists():
    try:
        correlated=json.loads(cf.read_text(errors="ignore")).get("findings",[])
    except Exception:
        correlated=[]

# Optional scanner raw text for dashboard
extra_reports={}
for key, rel in {
    "Nikto":"http/nikto.txt", "HTTPX":"http/httpx.txt", "WhatWeb":"http/whatweb.txt",
    "WAF/CDN":"http/waf.txt", "testssl.sh":"tls/testssl.txt", "Subfinder":"subdomains/subfinder.txt",
    "DNSX":"subdomains/dnsx.txt", "Katana":"crawl/urls.txt", "FFUF":"fuzz/ffuf.txt", "WPScan":"wpscan/wpscan.txt",
    "Correlation":"correlation/findings.txt"
}.items():
    fp=report/rel
    extra_reports[key]=fp.read_text(errors="ignore") if fp.exists() else "Report unavailable."

# DNS
dns_path = report / "dns/dns-recon.txt"
dns_text = dns_path.read_text(errors="ignore") if dns_path.exists() else "DNS report unavailable."

# HTTP headers
http_path = report / "http/http-recon.txt"
http_text = http_path.read_text(errors="ignore") if http_path.exists() else ""
headers = {}
for h in ["strict-transport-security", "content-security-policy", "x-frame-options",
          "x-content-type-options", "referrer-policy", "permissions-policy"]:
    m = re.search(r"^" + re.escape(h) + r":\s*(.+)$", http_text, re.I | re.M)
    headers[h] = m.group(1).strip() if m else None

# TLS certificate / protocol evidence
tls_path = report / "tls/tls-recon.txt"
tls_text = tls_path.read_text(errors="ignore") if tls_path.exists() else ""
tls12 = bool(re.search(r"Protocol(?:\s+version)?\s*:\s*TLSv1\.2|New,\s*TLSv1\.2", tls_text, re.I))
tls13 = bool(re.search(r"Protocol(?:\s+version)?\s*:\s*TLSv1\.3|New,\s*TLSv1\.3", tls_text, re.I))

# severity counts / risk engine
sev_order = ["critical", "high", "medium", "low", "info"]
counts = {s: 0 for s in sev_order}
score = 0
if correlated:
    for f in correlated:
        ss = f.get("severity", "info")
        if ss == "informational": ss = "info"
        if ss in counts: counts[ss] += 1
        base={"critical":25,"high":15,"medium":7,"low":2,"info":0}.get(ss,0)
        conf={"high":1.0,"medium":0.75,"low":0.5}.get(str(f.get("confidence","medium")).lower(),0.75)
        multi=1.10 if len(f.get("sources",[])) >= 2 else 1.0
        score += base * conf * multi
    score=min(100, round(score))
else:
    for f in nuclei + zap:
        ss = f["severity"]
        if ss == "informational": ss = "info"
        if ss in counts: counts[ss] += 1
    score = min(100, counts["critical"] * 25 + counts["high"] * 15 + counts["medium"] * 7 + counts["low"] * 2)
if score >= 70: risk = "CRITICAL"
elif score >= 40: risk = "HIGH"
elif score >= 20: risk = "MEDIUM"
elif score > 0: risk = "LOW"
else: risk = "PASS"
total = len(correlated) if correlated else sum(counts.values())
raw_count = 0
try:
    raw_count = int(json.loads(cf.read_text(errors='ignore')).get('raw_count', 0)) if cf.exists() else len(nuclei)+len(zap)
except Exception:
    raw_count = len(nuclei)+len(zap)
scanner_status = {}
try:
    scanner_status = json.loads(cf.read_text(errors='ignore')).get('scanner_status', {}) if cf.exists() else {}
except Exception:
    scanner_status = {}
scanner_ok = sum(1 for v in scanner_status.values() if v)
scanner_total = len(scanner_status)

def correlated_rows(items):
    rows=[]
    for f in items:
        sev=f.get('severity','info'); cls=sev if sev in ('critical','high','medium','low','info') else 'info'
        sources=', '.join(f.get('sources',[])); conf=f.get('confidence','medium').upper()
        rows.append(f'<tr><td><span class="badge {cls}">{esc(sev.upper())}</span></td><td><b>{esc(f.get("name",""))}</b><div class="muted">{esc(sources)} · confidence {esc(conf)}</div></td><td>{esc(f.get("evidence",f.get("url","")))}</td><td>{esc(f.get("solution","") or "Validate manually and review scanner guidance.")}</td></tr>')
    return ''.join(rows) or '<tr><td colspan="4" class="muted">No correlated findings.</td></tr>'

def findings_rows(items, source):
    rows = []
    for f in items:
        sev = f["severity"]
        if sev == "informational":
            sev = "info"
        cls = sev if sev in ("critical", "high", "medium", "low", "info") else "info"
        evidence = f.get("matched") or f.get("url", "")
        fix = f.get("solution", "")
        if source == "Nuclei":
            refs = f.get("reference", [])
            if isinstance(refs, list):
                refs = " ".join(map(str, refs))
            fix = refs or "Review the Nuclei template guidance and validate the finding manually."
        rows.append(
            f'<tr><td><span class="badge {cls}">{esc(sev.upper())}</span></td>'
            f'<td><b>{esc(f["name"])}</b><div class="muted">{esc(source)}</div></td>'
            f'<td>{esc(evidence)}</td><td>{esc(fix)}</td></tr>'
        )
    return "".join(rows) or '<tr><td colspan="4" class="muted">No findings in this source.</td></tr>'

# security header rows
header_rows = ""
for name, val in headers.items():
    status = "PASS" if val else "MISSING"
    cls = "pass" if val else "fail"
    header_rows += f'<tr><td>{esc(name)}</td><td><span class="badge {cls}">{status}</span></td><td>{esc(val or "Header not observed")}</td></tr>'

raw = [
    ("Nmap XML", "nmap/nmap.xml"), ("Nmap text", "nmap/nmap.nmap"), ("Nmap Vulners", "nmap/nmap-vulners.txt"),
    ("DNS", "dns/dns-recon.txt"), ("HTTP", "http/http-recon.txt"),
    ("TLS", "tls/tls-recon.txt"), ("Nuclei TXT", "nuclei/nuclei.txt"),
    ("Nuclei JSON", "nuclei/nuclei.json"), ("ZAP HTML", "zap/zap-report.html"),
    ("ZAP JSON", "zap/zap-report.json"), ("Nikto", "http/nikto.txt"), ("HTTPX", "http/httpx.json"),
    ("WhatWeb", "http/whatweb.txt"), ("WAF/CDN", "http/waf.txt"), ("testssl", "tls/testssl.txt"),
    ("Subfinder", "subdomains/subfinder.txt"), ("DNSX", "subdomains/dnsx.txt"), ("Katana", "crawl/urls.txt"),
    ("FFUF", "fuzz/ffuf.json"), ("WPScan", "wpscan/wpscan.json"), ("Correlated findings", "correlation/findings.json"),
    ("Scan log", "scan.log"),
]
raw_links = " ".join(f'<a class="raw" href="{esc(p)}">{esc(n)}</a>' for n, p in raw if (report / p).exists())

scanner_rows_parts=[]
for k,v in scanner_status.items():
    cls='pass' if v else 'warn'; label='DATA' if v else 'NO DATA'
    scanner_rows_parts.append(f'<tr><td>{esc(k)}</td><td><span class="badge {cls}">{label}</span></td></tr>')
scanner_rows=''.join(scanner_rows_parts) or '<tr><td colspan="2" class="muted">No scanner inventory.</td></tr>'

port_rows = "".join(
    f'<tr><td>{esc(x["port"])}</td><td>{esc(x["proto"])}</td><td>{esc(x["service"])}</td>'
    f'<td>{esc((x["product"] + " " + x["version"]).strip())}</td></tr>'
    for x in ports
) or '<tr><td colspan="4" class="muted">No open TCP/UDP services reported by Nmap.</td></tr>'

nmap_count = len(ports)
tls_status = "PASS" if (tls12 or tls13) else "REVIEW"
tls_cls = "pass" if tls_status == "PASS" else "warn"

executive = (
    "No automated findings were recorded by Nuclei or ZAP. This does not prove the target is secure; "
    "manual validation and authenticated testing may identify issues outside automated coverage."
    if total == 0 else
    f"The automated assessment identified {total} deduplicated finding(s) from {raw_count} raw scanner observations. The highest observed automated risk is "
    f"<b>{esc(risk)}</b>. Findings should be manually validated before being treated as confirmed vulnerabilities."
)

html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(domain)} — Pentest Security Assessment</title>
<style>
:root {{
    --bg: #070b12; --bg-soft: #0b111c; --panel: #0e1623; --panel-hover: #121d2d;
    --panel-soft: #111b2a; --border: #1d2a3a; --border-light: #26364a;
    --text: #e7edf5; --text-soft: #c1ccd9; --muted: #718096;
    --accent: #22c55e; --accent-soft: rgba(34, 197, 94, .10);
    --blue: #38bdf8; --blue-soft: rgba(56, 189, 248, .10);
    --critical: #ff3b5c; --critical-soft: rgba(255, 59, 92, .12);
    --high: #ff7a18; --high-soft: rgba(255, 122, 24, .12);
    --medium: #f5c542; --medium-soft: rgba(245, 197, 66, .12);
    --low: #22c55e; --low-soft: rgba(34, 197, 94, .12);
    --info: #38bdf8; --info-soft: rgba(56, 189, 248, .12);
    --shadow: 0 20px 60px rgba(0, 0, 0, .28);
    --radius: 14px;
}}
* {{ box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}
body {{
    margin: 0; min-height: 100vh;
    background:
        radial-gradient(circle at 15% 10%, rgba(34, 197, 94, .06), transparent 30%),
        radial-gradient(circle at 85% 15%, rgba(56, 189, 248, .05), transparent 28%),
        linear-gradient(180deg, #070b12 0%, #080d15 45%, #060a10 100%);
    color: var(--text);
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    font-size: 14px; line-height: 1.6;
}}
::-webkit-scrollbar {{ width: 8px; height: 8px; }}
::-webkit-scrollbar-track {{ background: #080d15; }}
::-webkit-scrollbar-thumb {{ background: #263447; border-radius: 20px; }}
::-webkit-scrollbar-thumb:hover {{ background: #34465c; }}
header {{
    position: relative; padding: 42px 5vw 38px;
    background: linear-gradient(135deg, rgba(14, 22, 35, .98), rgba(7, 11, 18, .98));
    border-bottom: 1px solid var(--border); overflow: hidden;
}}
header::before {{
    content: ""; position: absolute; width: 420px; height: 420px; right: -150px; top: -220px;
    background: radial-gradient(circle, rgba(34, 197, 94, .11), transparent 68%);
    pointer-events: none;
}}
header::after {{
    content: ""; position: absolute; left: 0; right: 0; bottom: 0; height: 1px;
    background: linear-gradient(90deg, transparent, rgba(34, 197, 94, .5), transparent);
}}
.brand {{
    position: relative; display: flex; align-items: center; gap: 12px;
    font-size: 25px; font-weight: 800; letter-spacing: -.02em;
}}
.brand::before {{
    content: ">_"; display: inline-flex; align-items: center; justify-content: center;
    width: 38px; height: 38px; border: 1px solid rgba(34, 197, 94, .35); border-radius: 9px;
    background: var(--accent-soft); color: var(--accent);
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    font-size: 15px; box-shadow: 0 0 25px rgba(34, 197, 94, .08);
}}
.subtitle {{
    position: relative; margin-top: 7px; margin-left: 50px; color: var(--muted);
    font-size: 12px; letter-spacing: .08em; text-transform: uppercase;
}}
nav {{
    position: sticky; top: 0; z-index: 100; display: flex; align-items: center;
    min-height: 52px; padding: 8px 4vw; background: rgba(7, 11, 18, .90);
    border-bottom: 1px solid var(--border); backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px); overflow-x: auto; white-space: nowrap;
}}
nav::-webkit-scrollbar {{ height: 0; }}
nav a {{
    position: relative; display: inline-flex; align-items: center; height: 36px;
    padding: 0 12px; color: var(--muted); text-decoration: none; font-size: 12px;
    font-weight: 600; border-radius: 7px; transition: color .2s ease, background .2s ease;
}}
nav a:hover {{ color: var(--text); background: rgba(255, 255, 255, .04); }}
nav a:first-child {{ color: var(--accent); }}
.container {{ width: min(1480px, calc(100% - 40px)); margin: 0 auto; padding: 30px 0 70px; }}
.meta {{
    position: relative; margin-bottom: 24px; padding: 22px 24px;
    background: linear-gradient(135deg, rgba(14, 22, 35, .98), rgba(11, 17, 28, .98));
    border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden;
}}
.meta::before {{
    content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
    background: linear-gradient(180deg, var(--accent), transparent);
}}
.meta b {{ color: var(--text); font-weight: 650; }}
.meta a {{ color: var(--blue); text-decoration: none; }}
.meta a:hover {{ text-decoration: underline; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(175px, 1fr)); gap: 14px; }}
.stat {{
    position: relative; min-height: 120px; padding: 19px;
    background: linear-gradient(145deg, var(--panel), var(--bg-soft));
    border: 1px solid var(--border); border-radius: var(--radius);
    box-shadow: 0 10px 35px rgba(0, 0, 0, .16); overflow: hidden;
    transition: transform .2s ease, border-color .2s ease, background .2s ease;
}}
.stat::after {{
    content: ""; position: absolute; width: 100px; height: 100px; right: -50px; bottom: -60px;
    background: radial-gradient(circle, rgba(34, 197, 94, .08), transparent 70%);
}}
.stat:hover {{ transform: translateY(-2px); border-color: var(--border-light); background: var(--panel-hover); }}
.label {{ color: var(--muted); font-size: 10px; font-weight: 700; letter-spacing: .11em; text-transform: uppercase; }}
.value {{ margin-top: 8px; color: var(--text); font-size: 30px; font-weight: 800; line-height: 1.1; }}
.value .muted {{ margin-left: 3px; color: var(--muted); font-size: 15px; font-weight: 500; }}
.risk {{ color: var(--text); }}
.risk.CRITICAL {{ color: var(--critical); text-shadow: 0 0 20px rgba(255, 59, 92, .25); }}
.risk.HIGH {{ color: var(--high); text-shadow: 0 0 20px rgba(255, 122, 24, .20); }}
.risk.MEDIUM {{ color: var(--medium); }}
.risk.LOW {{ color: var(--low); }}
.risk.PASS {{ color: var(--accent); text-shadow: 0 0 20px rgba(34, 197, 94, .18); }}
section {{ margin-top: 38px; scroll-margin-top: 80px; }}
h2 {{
    display: flex; align-items: center; gap: 10px; margin: 0 0 14px;
    color: var(--text); font-size: 18px; font-weight: 750; letter-spacing: -.01em;
}}
h2::before {{
    content: ""; width: 4px; height: 19px; border-radius: 4px;
    background: var(--accent); box-shadow: 0 0 12px rgba(34, 197, 94, .25);
}}
h3 {{ margin-top: 20px; color: var(--text); font-size: 14px; }}
.panel {{
    background: rgba(14, 22, 35, .92); border: 1px solid var(--border);
    border-radius: var(--radius); box-shadow: 0 14px 40px rgba(0, 0, 0, .16); overflow: hidden;
}}
.panel + .panel {{ margin-top: 14px; }}
.panel-head {{
    display: flex; align-items: center; min-height: 48px; padding: 0 18px;
    background: linear-gradient(90deg, rgba(255,255,255,.025), transparent);
    border-bottom: 1px solid var(--border); color: var(--text-soft);
    font-size: 12px; font-weight: 700; letter-spacing: .03em;
}}
.panel-head::before {{
    content: ""; width: 6px; height: 6px; margin-right: 9px; border-radius: 50%;
    background: var(--accent); box-shadow: 0 0 8px rgba(34, 197, 94, .35);
}}
.pad {{ padding: 20px; }}
.notice {{
    padding: 19px 20px;
    background: linear-gradient(135deg, rgba(34, 197, 94, .06), rgba(56, 189, 248, .025));
    border-left: 3px solid var(--accent); border-radius: 8px; color: var(--text-soft);
}}
table {{ width: 100%; border-collapse: separate; border-spacing: 0; }}
thead {{ background: rgba(255, 255, 255, .025); }}
th {{
    padding: 11px 14px; color: #64748b; font-size: 10px; font-weight: 800;
    letter-spacing: .09em; text-transform: uppercase; border-bottom: 1px solid var(--border);
}}
td {{
    padding: 13px 14px; color: var(--text-soft); font-size: 13px;
    border-bottom: 1px solid rgba(38, 50, 71, .65); vertical-align: top;
}}
tbody tr {{ transition: background .15s ease; }}
tbody tr:hover {{ background: rgba(255, 255, 255, .025); }}
tbody tr:last-child td {{ border-bottom: none; }}
td b {{ color: var(--text); font-weight: 650; }}
.muted {{ color: var(--muted); }}
.badge {{
    display: inline-flex; align-items: center; justify-content: center; min-width: 72px;
    padding: 4px 9px; border-radius: 6px;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    font-size: 9px; font-weight: 800; letter-spacing: .05em; border: 1px solid transparent;
}}
.badge.critical {{ color: #ff8ca0; background: var(--critical-soft); border-color: rgba(255, 59, 92, .22); }}
.badge.high {{ color: #ffad70; background: var(--high-soft); border-color: rgba(255, 122, 24, .22); }}
.badge.medium {{ color: #f7d96b; background: var(--medium-soft); border-color: rgba(245, 197, 66, .20); }}
.badge.low {{ color: #70e59a; background: var(--low-soft); border-color: rgba(34, 197, 94, .20); }}
.badge.info {{ color: #7ddcff; background: var(--info-soft); border-color: rgba(56, 189, 248, .20); }}
.badge.pass {{ color: #70e59a; background: var(--low-soft); border-color: rgba(34, 197, 94, .20); }}
.badge.fail {{ color: #ff8ca0; background: var(--critical-soft); border-color: rgba(255, 59, 92, .20); }}
.badge.warn {{ color: #f7d96b; background: var(--medium-soft); border-color: rgba(245, 197, 66, .20); }}
pre {{
    margin: 0; padding: 20px; max-height: 540px; overflow: auto; background: #080d15; color: #b7c4d5;
    font-family: "SFMono-Regular", "Cascadia Code", Consolas, "Liberation Mono", monospace;
    font-size: 12px; line-height: 1.7; white-space: pre-wrap; word-break: break-word;
    border-top: 1px solid rgba(38, 50, 71, .45);
}}
pre::selection {{ background: rgba(34, 197, 94, .22); }}
.raw {{
    position: relative; display: inline-flex; align-items: center; margin: 4px; padding: 9px 12px;
    background: rgba(255,255,255,.02); border: 1px solid var(--border); border-radius: 8px;
    color: var(--text-soft); font-size: 11px; font-weight: 600; text-decoration: none;
    transition: color .2s ease, background .2s ease, border-color .2s ease, transform .2s ease;
}}
.raw::before {{ content: "↗"; margin-right: 7px; color: var(--accent); font-size: 11px; }}
.raw:hover {{ color: white; background: var(--accent-soft); border-color: rgba(34, 197, 94, .25); transform: translateY(-1px); }}
ul {{ padding-left: 22px; color: var(--text-soft); }}
li {{ margin: 6px 0; }}
li::marker {{ color: var(--accent); }}
footer {{
    margin-top: 30px; padding: 35px 20px; color: #4f6074; text-align: center;
    font-family: "SFMono-Regular", Consolas, monospace; font-size: 10px;
    letter-spacing: .05em; border-top: 1px solid var(--border);
}}
@media (max-width: 900px) {{
    .container {{ width: calc(100% - 28px); }}
    header {{ padding: 30px 20px; }}
    .brand {{ font-size: 21px; }}
    .subtitle {{ margin-left: 50px; }}
    .grid {{ grid-template-columns: repeat(auto-fit, minmax(145px, 1fr)); }}
}}
@media (max-width: 600px) {{
    body {{ font-size: 13px; }}
    .container {{ width: calc(100% - 20px); padding-top: 20px; }}
    .brand {{ font-size: 18px; }}
    .brand::before {{ width: 32px; height: 32px; }}
    .subtitle {{ margin-left: 44px; font-size: 9px; }}
    .grid {{ grid-template-columns: repeat(2, 1fr); }}
    .stat {{ min-height: 100px; padding: 15px; }}
    .value {{ font-size: 24px; }}
    table {{ min-width: 680px; }}
    .panel {{ overflow-x: auto; }}
}}
@media print {{
    :root {{
        --bg: #ffffff; --panel: #ffffff; --panel-soft: #f5f7fa; --border: #d8dee7;
        --text: #111827; --text-soft: #374151; --muted: #6b7280;
    }}
    body {{ background: white !important; color: #111827; font-size: 10px; }}
    header {{ padding: 25px; background: white !important; border-bottom: 2px solid #111827; }}
    .brand, h2, h3, td, .meta b, .panel-head {{ color: #111827 !important; }}
    nav {{ display: none; }}
    .container {{ width: 100%; padding: 15px 0 30px; }}
    .meta, .panel, .stat {{ background: white !important; color: #111827; border: 1px solid #d8dee7; box-shadow: none; break-inside: avoid; }}
    .stat:hover {{ transform: none; }}
    .panel {{ margin-bottom: 16px; }}
    pre {{ max-height: none; background: #f5f7fa; color: #111827; border: 1px solid #d8dee7; font-size: 8px; }}
    section {{ break-inside: avoid; }}
    table {{ min-width: 0; }}
    a {{ color: #111827 !important; }}
    .raw {{ display: none; }}
    footer {{ color: #6b7280; }}
}}
@media (prefers-reduced-motion: reduce) {{
    *, *::before, *::after {{ scroll-behavior: auto !important; transition: none !important; }}
}}
</style>
</head>
<body>
<header>
<div class="brand">INTERNAL SECURITY ASSESSMENT</div>
<div class="subtitle">Automated Security Testing & Vulnerability Assessment</div>
</header>
<nav>
<a href="#overview">Overview</a><a href="#executive">Executive Summary</a><a href="#coverage">Coverage</a><a href="#findings">Findings</a>
<a href="#nmap">Nmap</a><a href="#dns">DNS</a><a href="#http">HTTP</a><a href="#tls">TLS</a><a href="#discovery">Discovery</a><a href="#correlation">Correlation</a>
<a href="#methodology">Methodology</a><a href="#raw">Raw Reports</a>
</nav>
<div class="container">
<div class="meta" id="overview">
<b>Target:</b> <a href="{esc(url)}" target="_blank">{esc(url)}</a><br>
<b>Domain:</b> {esc(domain)}<br>
<b>Assessment time:</b> {esc(start)}<br>
<b>Completed:</b> {esc(end_time)}<br>
<b>Duration:</b> {esc(duration_seconds)} seconds<br>
<b>Profiles:</b> {esc(scan_profile)} / Nuclei {esc(nuclei_profile)}<br>
<b>Scope:</b> External unauthenticated assessment of the specified target.<br>
<b>Assessment type:</b> Automated reconnaissance and vulnerability scanning.
</div>
<div class="grid">
<div class="stat"><div class="label">Overall Risk</div><div class="value risk {risk}">{esc(risk)}</div></div>
<div class="stat"><div class="label">Risk Score</div><div class="value">{score}<span class="muted">/100</span></div></div>
<div class="stat"><div class="label">Critical</div><div class="value">{counts["critical"]}</div></div>
<div class="stat"><div class="label">High</div><div class="value">{counts["high"]}</div></div>
<div class="stat"><div class="label">Medium</div><div class="value">{counts["medium"]}</div></div>
<div class="stat"><div class="label">Low</div><div class="value">{counts["low"]}</div></div>
<div class="stat"><div class="label">Info</div><div class="value">{counts["info"]}</div></div>
<div class="stat"><div class="label">Raw Observations</div><div class="value">{raw_count}</div></div>
<div class="stat"><div class="label">Open Services</div><div class="value">{nmap_count}</div></div>
</div>
<section id="executive"><h2>Executive Summary</h2><div class="panel"><div class="pad">{executive}</div></div></section>
<section id="coverage"><h2>Scanner Coverage</h2><div class="panel"><table><thead><tr><th>Scanner</th><th>Status</th></tr></thead><tbody>{scanner_rows}</tbody></table><div class="pad"><b>Available:</b> {scanner_ok}/{scanner_total}</div></div></section>
<section id="findings"><h2>Security Findings</h2>
<div class="panel"><div class="panel-head">Correlated / Deduplicated Findings</div>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Remediation</th></tr></thead>
<tbody>{correlated_rows(correlated)}</tbody></table></div>
<div class="panel" style="margin-top:14px">
<div class="panel-head">Nuclei Findings</div>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Reference / Guidance</th></tr></thead>
<tbody>{findings_rows(nuclei,"Nuclei")}</tbody></table>
</div>
<div class="panel" style="margin-top:14px">
<div class="panel-head">OWASP ZAP Findings</div>
<table><thead><tr><th>Severity</th><th>Finding</th><th>URL</th><th>Remediation</th></tr></thead>
<tbody>{findings_rows(zap,"OWASP ZAP")}</tbody></table>
</div></section>
<section id="nmap"><h2>Infrastructure — Nmap</h2>
<div class="panel"><div class="panel-head">Open Services</div>
<table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product / Version</th></tr></thead><tbody>{port_rows}</tbody></table></div></section>
<section id="dns"><h2>DNS Security Posture</h2>
<div class="panel"><div class="pad"><pre>{esc(dns_text)}</pre></div></div></section>
<section id="http"><h2>HTTP Security Posture</h2>
<div class="panel"><div class="panel-head">Observed Security Headers</div>
<table><thead><tr><th>Header</th><th>Status</th><th>Observed Value</th></tr></thead><tbody>{header_rows}</tbody></table></div>
<div class="panel" style="margin-top:14px"><div class="panel-head">Raw HTTP Recon</div><pre>{esc(http_text)}</pre></div>
</section>
<section id="tls"><h2>TLS Security Posture</h2>
<div class="grid">
<div class="stat"><div class="label">TLS 1.2</div><div class="value"><span class="badge {tls_cls}">{"OBSERVED" if tls12 else "NOT OBSERVED"}</span></div></div>
<div class="stat"><div class="label">TLS 1.3</div><div class="value"><span class="badge {tls_cls}">{"OBSERVED" if tls13 else "NOT OBSERVED"}</span></div></div>
<div class="stat"><div class="label">TLS Posture</div><div class="value"><span class="badge {tls_cls}">{tls_status}</span></div></div>
</div>
<div class="panel" style="margin-top:14px"><div class="panel-head">TLS Evidence</div><pre>{esc(tls_text)}</pre></div>
</section>
<section id="discovery"><h2>Extended Discovery & Scanners</h2>
<div class="panel"><div class="panel-head">Nikto</div><pre>{esc(extra_reports["Nikto"])}</pre></div>
<div class="panel"><div class="panel-head">HTTPX</div><pre>{esc(extra_reports["HTTPX"])}</pre></div>
<div class="panel"><div class="panel-head">WhatWeb</div><pre>{esc(extra_reports["WhatWeb"])}</pre></div>
<div class="panel"><div class="panel-head">WAF / CDN</div><pre>{esc(extra_reports["WAF/CDN"])}</pre></div>
<div class="panel"><div class="panel-head">Subfinder</div><pre>{esc(extra_reports["Subfinder"])}</pre></div>
<div class="panel"><div class="panel-head">DNSX</div><pre>{esc(extra_reports["DNSX"])}</pre></div>
<div class="panel"><div class="panel-head">Katana URLs</div><pre>{esc(extra_reports["Katana"])}</pre></div>
<div class="panel"><div class="panel-head">FFUF</div><pre>{esc(extra_reports["FFUF"])}</pre></div>
<div class="panel"><div class="panel-head">WPScan</div><pre>{esc(extra_reports["WPScan"])}</pre></div>
</section>
<section id="correlation"><h2>Correlation & Risk Engine</h2>
<div class="panel"><div class="pad"><b>Raw findings:</b> {esc(str(raw_count))}<br><b>Deduplicated findings:</b> {esc(str(len(correlated)))}<br><b>Risk score:</b> {score}/100<br><b>Profile:</b> {esc(scan_profile)}</div><pre>{esc(extra_reports["Correlation"])}</pre></div></section>
<section id="methodology"><h2>Methodology & Limitations</h2>
<div class="panel"><div class="pad">
<h3>Tools</h3>
<ul>
<li>Nmap — network/service enumeration</li>
<li>DNS utilities — DNS record reconnaissance</li>
<li>curl — HTTP response and security-header inspection</li>
<li>OpenSSL — TLS certificate/protocol inspection</li>
<li>Nikto — web server security checks</li>
<li>httpx — HTTP probing and technology fingerprinting</li>
<li>WhatWeb — web technology fingerprinting</li>
<li>testssl.sh — TLS configuration assessment</li>
<li>Subfinder + DNSX — passive subdomain and DNS discovery</li>
<li>Katana — web crawling and URL discovery</li>
<li>FFUF — optional content discovery</li>
<li>WPScan — optional WordPress vulnerability assessment</li>
<li>Nuclei — template-based vulnerability and misconfiguration detection</li>
<li>OWASP ZAP Baseline — web application passive/baseline assessment</li>
<li>Correlation engine — finding deduplication, confidence and risk scoring</li>
</ul>
<h3>Important limitations</h3>
<p>This is an automated assessment and is <b>not equivalent to a full manual penetration test</b>. Results can contain false positives and false negatives. No authentication bypass, business-logic testing, destructive exploitation, or intrusive exploitation is performed by this default profile.</p>
<p>Findings should be validated manually before remediation or risk acceptance decisions.</p>
</div></div></section>
<section id="raw"><h2>Raw Evidence & Reports</h2><div class="panel"><div class="pad">{raw_links}</div></div></section>
</div>
<footer>Generated by Internal Security Assessment Platform v5.0 — {esc(start)}</footer>
</body></html>
"""

Path(output).write_text(html_doc, encoding="utf-8")
print(f"[OK] Dashboard generated: {output}")
PY

# -------------------------- Summary --------------------------
cat > "$REPORT_DIR/SUMMARY.md" <<SUMMARY_EOF
# Internal Security Assessment v5.0
Target: $TARGET_URL
Domain: $TARGET_DOMAIN
Started: $START_TIME
Scan profile: $SCAN_PROFILE
Nuclei profile: $NUCLEI_PROFILE
Completed: $END_TIME
Duration: ${DURATION_SECONDS}s

## Main Report
Open \`report.html\`.

## Scanner Outputs
- Nmap: \`nmap/\`
- DNS: \`dns/dns-recon.txt\`
- HTTP: \`http/http-recon.txt\`
- TLS: \`tls/tls-recon.txt\`
- Nuclei: \`nuclei/\`
- OWASP ZAP: \`zap/\`
- Execution log: \`scan.log\`

## Scope
External unauthenticated automated assessment of the specified target.

## Important
This report is not a substitute for a manual penetration test. Validate findings before treating them as confirmed vulnerabilities.
SUMMARY_EOF

echo
echo "============================================================"
echo " SCAN SELESAI"
echo "============================================================"
echo "Dashboard : $HTML_REPORT"
echo "Directory : $REPORT_DIR"
echo
find "$REPORT_DIR" -maxdepth 2 -type f | sort
echo
echo "Open with:"
echo "firefox '$HTML_REPORT'"
echo "============================================================"
