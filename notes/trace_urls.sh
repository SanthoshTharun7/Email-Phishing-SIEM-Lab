#!/usr/bin/env bash
set -e

cd ~/phish-lab

echo "=== TRACING TOP 6 LIVE URLS FROM OPENPHISH ==="
head -n 6 samples/urls.txt | while read -r url; do
  [ -z "$url" ] && continue
  defanged=$(echo "$url" | sed 's/http/hxxp/g; s/\./[.]/g')
  echo ""
  echo "Target: $defanged"
  docker run --rm curlimages/curl -sL -o /dev/null --max-time 10 --max-redirs 5 -A "Mozilla/5.0" \
    -w '  Final URL   : %{url_effective}\n  HTTP Status : %{http_code}\n  Redirects   : %{num_redirects}\n  Remote IP   : %{remote_ip}\n' "$url" \
    | sed 's/http/hxxp/g'
done | tee notes/live_url_traces.txt
