#!/bin/bash
# MCPFuzz Wave 1 — Tier A, No API Key (71 targets)
# Sorted by stars descending — highest impact first.
# Run: bash mcpfuzz-wave1.sh
# Resume after interruption: bash mcpfuzz-wave1.sh  (already-scanned targets are skipped)

set -euo pipefail

export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/Users/agentprime/.local/bin:/usr/local/bin:/usr/bin:/bin"

MCPFUZZ="python3 -m mcpfuzz"
RESULTS_DIR="/Users/agentprime/Desktop/mcpfuzz/wave1-results"
SUMMARY="$RESULTS_DIR/wave1-summary-$(date +%Y%m%d).md"
POC_DIR="$RESULTS_DIR/poc"
LOG="$RESULTS_DIR/wave1-run.log"

# LLM judge — uses local Ollama daemon with minimax-m2.5:cloud (same as OpenClaw).
# Ollama routes :cloud model inference to cloud GPUs automatically — no API key needed.
# Requires: ollama is running + signed in (ollama signin).
# Falls back to Anthropic key if ANTHROPIC_API_KEY is set and Ollama is unavailable.
LLM_PROVIDER="ollama"
LLM_MODEL="minimax-m2.5:cloud"
LLM_KEY=""  # Not needed — Ollama handles auth via local daemon

mkdir -p "$RESULTS_DIR" "$POC_DIR"

log()  { echo "[$(date -u +%H:%M:%S)] $1" | tee -a "$LOG"; }
logn() { printf "[$(date -u +%H:%M:%S)] $1" | tee -a "$LOG"; }

log "================================================================"
log "MCPFuzz Wave 1 — Tier A Targets"
log "Results: $RESULTS_DIR"
log "LLM judge: ollama/${LLM_MODEL} via local daemon (minimax-m2.5:cloud → Ollama cloud GPU)"
log "================================================================"
echo ""

CONFIRMED=0
POTENTIAL=0
ERRORS=0
SKIPPED=0
TOTAL=71

scan_target() {
  local tid="$1"
  local stars="$2"
  local pkg="$3"
  local cmd="$4"
  local num="$5"

  local out_file="$RESULTS_DIR/${tid}-$(echo "$pkg" | tr '/@' '--').json"

  # Resume: skip if already scanned successfully
  if [ -f "$out_file" ] && [ -s "$out_file" ]; then
    log "[$num/$TOTAL] SKIP $tid ($pkg) — already scanned"
    ((SKIPPED++)) || true
    return
  fi

  log "[$num/$TOTAL] $tid ★$stars  $pkg"
  log "  cmd: $cmd"

  # Always enable LLM judge via local Ollama daemon (no key required for :cloud models)
  local llm_args="--llm-provider $LLM_PROVIDER --llm-model $LLM_MODEL"

  # 4-minute timeout per target — enough for all 12 modules
  # macOS: use perl-based timeout (no GNU coreutils required)
  local exit_code=0
  perl -e 'alarm shift; exec @ARGV' 240 \
    $MCPFUZZ scan \
    -s "$cmd" \
    --output json \
    --out "$out_file" \
    --poc-dir "$POC_DIR" \
    $llm_args \
    2>>"$LOG" || exit_code=$?

  if [ $exit_code -eq 142 ]; then
    log "  → TIMEOUT (240s)"
    echo '{"error":"timeout"}' > "$out_file"
    ((ERRORS++)) || true
    return
  fi

  if [ ! -s "$out_file" ]; then
    log "  → ERROR (no output, exit=$exit_code)"
    echo '{"error":"no_output","exit_code":'"$exit_code"'}' > "$out_file"
    ((ERRORS++)) || true
    return
  fi

  # Parse findings from JSON output
  local confirmed potential
  confirmed=$(python3 -c "
import json, sys
try:
    d = json.load(open('$out_file'))
    findings = d.get('findings', [])
    print(sum(1 for f in findings if f.get('status') == 'CONFIRMED'))
except: print(0)
" 2>/dev/null || echo 0)

  potential=$(python3 -c "
import json, sys
try:
    d = json.load(open('$out_file'))
    findings = d.get('findings', [])
    print(sum(1 for f in findings if f.get('status') == 'POTENTIAL'))
except: print(0)
" 2>/dev/null || echo 0)

  if [ "$confirmed" -gt 0 ]; then
    log "  → *** CONFIRMED: $confirmed finding(s) ***"
    ((CONFIRMED += confirmed)) || true
  elif [ "$potential" -gt 0 ]; then
    log "  → POTENTIAL: $potential finding(s)"
    ((POTENTIAL += potential)) || true
  else
    log "  → clean"
  fi

  echo ""
}

# ── Wave 1 targets (Tier A, no API key, sorted by stars desc) ────────────────

scan_target "T0202" "40331" "@chakra-ui/react-mcp"                          "npx -y @chakra-ui/react-mcp"                                    1
scan_target "T0213" "6585"  "cursor-talk-to-figma-mcp"                      "npx -y cursor-talk-to-figma-mcp"                                2
scan_target "T0221" "4609"  "@21st-dev/magic"                               "npx -y @21st-dev/magic"                                         3
scan_target "T0228" "2063"  "@perplexity-ai/mcp-server"                     "npx -y @perplexity-ai/mcp-server"                               4
scan_target "T0234" "1605"  "tavily-mcp"                                    "npx -y tavily-mcp"                                              5
scan_target "T0240" "1319"  "nerve-adk"                                     "uvx nerve-adk"                                                  6
scan_target "T0245" "1035"  "mcp-server-chatsum"                            "npx -y mcp-server-chatsum"                                      7
scan_target "T0246" "987"   "@bitbonsai/mcpvault"                           "npx -y @bitbonsai/mcpvault"                                     8
scan_target "T0248" "945"   "@jetbrains/mcp-proxy"                          "npx -y @jetbrains/mcp-proxy"                                    9
scan_target "T0249" "872"   "@suekou/mcp-notion-server"                     "npx -y @suekou/mcp-notion-server"                               10
scan_target "T0250" "848"   "@brave/brave-search-mcp-server"                "npx -y @brave/brave-search-mcp-server"                          11
scan_target "T0251" "760"   "context-portal-mcp"                            "uvx context-portal-mcp"                                         12
scan_target "T0252" "588"   "mcp-searxng"                                   "npx -y mcp-searxng"                                             13
scan_target "T0256" "524"   "dbt-mcp"                                       "uvx dbt-mcp"                                                    14
scan_target "T0257" "431"   "airtable-mcp-server"                           "npx -y airtable-mcp-server"                                     15
scan_target "T0258" "411"   "@doist/todoist-ai"                             "npx -y @doist/todoist-ai"                                       16
scan_target "T0259" "408"   "@openbnb/mcp-server-airbnb"                    "npx -y @openbnb/mcp-server-airbnb"                              17
scan_target "T0261" "274"   "@fangjunjie/ssh-mcp-server"                    "npx -y @fangjunjie/ssh-mcp-server"                              18
scan_target "T0262" "230"   "@mastergo/magic-mcp"                           "npx -y @mastergo/magic-mcp"                                     19
scan_target "T0263" "224"   "@xeroapi/xero-mcp-server"                      "npx -y @xeroapi/xero-mcp-server"                                20
scan_target "T0264" "220"   "phone-mcp"                                     "uvx phone-mcp"                                                  21
scan_target "T0267" "177"   "shopify-mcp"                                   "npx -y shopify-mcp"                                             22
scan_target "T0268" "174"   "@railway/mcp-server"                           "npx -y @railway/mcp-server"                                     23
scan_target "T0269" "157"   "agentql-mcp"                                   "npx -y agentql-mcp"                                             24
scan_target "T0270" "140"   "@aashari/mcp-server-atlassian-bitbucket"       "npx -y @aashari/mcp-server-atlassian-bitbucket"                 25
scan_target "T0272" "130"   "@browserstack/mcp-server"                      "npx -y @browserstack/mcp-server"                                26
scan_target "T0274" "108"   "@paretools/shared"                             "npx -y @paretools/shared"                                       27
scan_target "T0276" "103"   "aiwg"                                          "npx -y aiwg"                                                    28
scan_target "T0277" "101"   "@dynatrace-oss/dynatrace-mcp-server"           "npx -y @dynatrace-oss/dynatrace-mcp-server"                     29
scan_target "T0278" "98"    "@auth0/auth0-mcp-server"                       "npx -y @auth0/auth0-mcp-server"                                 30
scan_target "T0279" "97"    "mcpcat"                                        "npx -y mcpcat"                                                  31
scan_target "T0280" "95"    "deepl-mcp-server"                              "npx -y deepl-mcp-server"                                        32
scan_target "T0281" "95"    "@shortcut/mcp"                                 "npx -y @shortcut/mcp"                                           33
scan_target "T0282" "92"    "mcp-image"                                     "npx -y mcp-image"                                               34
scan_target "T0283" "90"    "@pnp/cli-microsoft365-mcp-server"              "npx -y @pnp/cli-microsoft365-mcp-server"                        35
scan_target "T0284" "88"    "firefox-devtools-mcp"                          "npx -y firefox-devtools-mcp"                                    36
scan_target "T0285" "86"    "openai-websearch-mcp"                          "uvx openai-websearch-mcp"                                       37
scan_target "T0286" "77"    "hostinger-api-mcp"                             "npx -y hostinger-api-mcp"                                       38
scan_target "T0287" "62"    "sugarai"                                       "uvx sugarai"                                                    39
scan_target "T0289" "60"    "@aashari/mcp-server-atlassian-jira"            "npx -y @aashari/mcp-server-atlassian-jira"                      40
scan_target "T0290" "50"    "@aashari/mcp-server-atlassian-confluence"      "npx -y @aashari/mcp-server-atlassian-confluence"                41
scan_target "T0291" "32"    "pytidb"                                        "uvx pytidb"                                                     42
scan_target "T0293" "28"    "@smartbear/mcp"                                "npx -y @smartbear/mcp"                                          43
scan_target "T0294" "26"    "@taazkareem/clickup-mcp-server"                "npx -y @taazkareem/clickup-mcp-server"                          44
scan_target "T0295" "25"    "@diskd-ai/email-mcp"                           "npx -y @diskd-ai/email-mcp"                                     45
scan_target "T0297" "22"    "@variflight-ai/variflight-mcp"                 "npx -y @variflight-ai/variflight-mcp"                           46
scan_target "T0298" "22"    "@lofder/dsers-mcp-product"                     "npx -y @lofder/dsers-mcp-product"                              47
scan_target "T0299" "21"    "@growthbook/mcp"                               "npx -y @growthbook/mcp"                                         48
scan_target "T0300" "20"    "@waiaas/mcp"                                   "npx -y @waiaas/mcp"                                             49
scan_target "T0302" "19"    "@rigour-labs/mcp"                              "npx -y @rigour-labs/mcp"                                        50
scan_target "T0304" "15"    "@nex-ai/nex"                                   "npx -y @nex-ai/nex"                                             51
scan_target "T0306" "6"     "@kernel.chat/kbot"                             "npx -y @kernel.chat/kbot"                                       52
scan_target "T0310" "4"     "@overpod/mcp-telegram"                         "npx -y @overpod/mcp-telegram"                                   53
scan_target "T0311" "3"     "@velvetmonkey/flywheel-memory"                 "npx -y @velvetmonkey/flywheel-memory"                           54
scan_target "T0315" "2"     "@structured-world/gitlab-mcp"                  "npx -y @structured-world/gitlab-mcp"                            55
scan_target "T0317" "1"     "agent-passport-system-mcp"                     "npx -y agent-passport-system-mcp"                               56
scan_target "T0318" "1"     "@cocaxcode/api-testing-mcp"                    "npx -y @cocaxcode/api-testing-mcp"                              57
scan_target "T0319" "1"     "bbox-mcp-server"                               "npx -y bbox-mcp-server"                                         58
scan_target "T0320" "1"     "@cocaxcode/logbook-mcp"                        "npx -y @cocaxcode/logbook-mcp"                                  59
scan_target "T0321" "0"     "@currents/mcp"                                 "npx -y @currents/mcp"                                           60
scan_target "T0325" "0"     "@intlayer/mcp"                                 "npx -y @intlayer/mcp"                                           61
scan_target "T0326" "0"     "@planu/cli"                                    "npx -y @planu/cli"                                              62
scan_target "T0327" "0"     "perp-cli"                                      "npx -y perp-cli"                                                63
scan_target "T0328" "0"     "ucn"                                           "npx -y ucn"                                                     64
scan_target "T0332" "0"     "@codefuturist/email-mcp"                       "npx -y @codefuturist/email-mcp"                                 65
scan_target "T0333" "0"     "forgecraft-mcp"                                "npx -y forgecraft-mcp"                                          66
scan_target "T0334" "0"     "@j0hanz/fetch-url-mcp"                         "npx -y @j0hanz/fetch-url-mcp"                                   67
scan_target "T0335" "0"     "@gleanwork/local-mcp-server"                   "npx -y @gleanwork/local-mcp-server"                             68
scan_target "T0336" "0"     "search-mcp-server"                             "npx -y search-mcp-server"                                       69
scan_target "T0337" "0"     "mcp-devutils"                                  "npx -y mcp-devutils"                                            70
scan_target "T0338" "0"     "nanmesh-mcp"                                   "npx -y nanmesh-mcp"                                             71

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
log "================================================================"
log "Wave 1 Complete"
log "  Confirmed findings : $CONFIRMED"
log "  Potential findings : $POTENTIAL"
log "  Errors / timeouts  : $ERRORS"
log "  Skipped (already)  : $SKIPPED"
log "================================================================"

# Build summary markdown
{
  echo "# MCPFuzz Wave 1 Summary"
  echo "Generated: $(date)"
  echo ""
  echo "| Stat | Count |"
  echo "|------|-------|"
  echo "| Confirmed findings | $CONFIRMED |"
  echo "| Potential findings | $POTENTIAL |"
  echo "| Errors / timeouts  | $ERRORS |"
  echo "| Skipped            | $SKIPPED |"
  echo ""
  echo "## Confirmed Findings"
  echo ""
  python3 -c "
import json, os, glob
results_dir = '$RESULTS_DIR'
for f in sorted(glob.glob(results_dir + '/T*.json')):
    try:
        d = json.load(open(f))
        for finding in d.get('findings', []):
            if finding.get('status') == 'CONFIRMED':
                pkg = os.path.basename(f).replace('.json','')
                print(f\"### {pkg}\")
                print(f\"- **Type:** {finding.get('type','')}\")
                print(f\"- **Severity:** {finding.get('severity','')}\")
                print(f\"- **CVSS:** {finding.get('cvss_score','')}\")
                print(f\"- **Description:** {finding.get('description','')}\")
                print()
    except: pass
" 2>/dev/null
} > "$SUMMARY"

log "Summary written to: $SUMMARY"
log "JSON results in:    $RESULTS_DIR/"
log "POC scripts in:     $POC_DIR/"
