#!/usr/bin/env bash
# nuget.sh — NuGet V3 registry tests
# Usage: source registries/nuget.sh; test_nuget "$BASE_URL"

test_nuget() {
    local base="$1"
    set_registry "nuget"
    echo ""
    echo "--- NuGet ---"

    # Service index (/v3/index.json)
    local svc_code
    svc_code=$(curl -s -o /dev/null -w "%{http_code}" "$base/nuget/v3/index.json")
    if [ "$svc_code" = "200" ]; then
        pass "service_index"
    else
        fail "service_index" "got $svc_code"
        return  # other tests depend on service index
    fi

    # URL rewrite — service index should reference NORA base URL
    local svc_body
    svc_body=$(curl -sf "$base/nuget/v3/index.json" 2>/dev/null || echo "")
    if echo "$svc_body" | grep -q "/nuget"; then
        pass "url_rewrite"
    else
        fail "url_rewrite" "service index does not reference /nuget paths"
    fi

    # Scheme preservation — rewritten URLs must NOT hardcode http:// when PUBLIC_URL is https://
    # Bug #256: old code stripped scheme and hardcoded http://, breaking HTTPS deployments
    # Strategy: extract all rewritten @id URLs, verify they don't mix schemes.
    # If NORA_PUBLIC_URL starts with https, rewritten URLs must also use https.
    local rewritten_urls
    rewritten_urls=$(echo "$svc_body" | python3 -c "
import sys,json
try:
    data = json.load(sys.stdin)
    for r in data.get('resources', []):
        url = r.get('@id', '')
        if '/nuget/' in url:
            print(url)
except: pass
" 2>/dev/null || echo "")
    if [ -n "$rewritten_urls" ]; then
        # Get the scheme actually used by NORA in rewritten URLs
        local first_url
        first_url=$(echo "$rewritten_urls" | head -1)
        local actual_scheme
        actual_scheme=$(echo "$first_url" | grep -oP '^https?')

        # All rewritten URLs must use the same scheme
        local scheme_ok=true
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            local url_scheme
            url_scheme=$(echo "$url" | grep -oP '^https?')
            if [ "$url_scheme" != "$actual_scheme" ]; then
                scheme_ok=false
                fail "url_scheme_consistent" "mixed schemes: $actual_scheme vs $url_scheme in: $url"
                break
            fi
        done <<< "$rewritten_urls"
        if [ "$scheme_ok" = true ]; then
            pass "url_scheme_consistent"
        fi

        # If PUBLIC_URL is https, verify NORA doesn't downgrade to http
        # (This catches Bug #256: extract_host() stripped scheme, hardcoded http://)
        if [ "${NORA_PUBLIC_URL:-}" != "" ]; then
            local public_scheme
            public_scheme=$(echo "$NORA_PUBLIC_URL" | grep -oP '^https?' || echo "")
            if [ "$public_scheme" = "https" ] && [ "$actual_scheme" = "http" ]; then
                fail "url_scheme_preserved" "PUBLIC_URL is https but rewritten URLs use http (Bug #256)"
            elif [ -n "$public_scheme" ]; then
                pass "url_scheme_preserved"
            fi
        else
            pass "url_scheme_preserved"
        fi
    else
        skip "url_scheme_consistent" "no rewritten URLs in service index"
        skip "url_scheme_preserved" "no rewritten URLs in service index"
    fi

    # Registration — package metadata for Newtonsoft.Json
    local reg_code
    reg_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "$base/nuget/v3/registration/newtonsoft.json/index.json")
    if [ "$reg_code" = "200" ]; then
        pass "registration"
    else
        skip "registration" "returned $reg_code (may need upstream)"
    fi

    # Flat container — version list
    local flat_code
    flat_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "$base/nuget/v3/flatcontainer/newtonsoft.json/index.json")
    if [ "$flat_code" = "200" ]; then
        pass "flatcontainer"
    else
        skip "flatcontainer" "returned $flat_code (may need upstream)"
    fi

    # .nupkg download
    local nupkg_code
    nupkg_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "$base/nuget/v3/flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg")
    if [ "$nupkg_code" = "200" ]; then
        pass "nupkg_download"
    else
        skip "nupkg_download" "returned $nupkg_code (may need upstream)"
    fi

    # Search
    local search_code
    search_code=$(curl -s -o /dev/null -w "%{http_code}" \
        "$base/nuget/v3/query?q=newtonsoft&take=5")
    if [ "$search_code" = "200" ]; then
        pass "search"
    else
        skip "search" "returned $search_code (may need upstream)"
    fi
}
