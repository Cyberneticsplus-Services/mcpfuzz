#!/bin/bash
# MCPFuzz Docker Batch 1 — Targets 1–10 (PostgreSQL)
# Scheduled: 10:45 PM IST 2026-03-29

# ── Absolute paths (cron runs with minimal PATH) ─────────────────────────────
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/Users/agentprime/.local/bin:/usr/local/bin:/usr/bin:/bin"

MCPFUZZ="/opt/homebrew/bin/mcpfuzz"
DOCKER="/usr/local/bin/docker"
ORB="/opt/homebrew/bin/orb"
RESULTS_DIR="/Users/agentprime/Desktop/mcpfuzz/docker-results"
OUTPUT="$RESULTS_DIR/batch1-$(date +%Y%m%d-%H%M).md"
PG_URL="postgresql://postgres:test@localhost/testdb"
PG_URL2="postgres://postgres:test@localhost/testdb?sslmode=disable"

mkdir -p "$RESULTS_DIR"

log() { echo "$1" | tee -a "$OUTPUT"; }
fail() { log "FATAL: $1"; exit 1; }

log "# MCPFuzz Docker Batch 1 — PostgreSQL Targets (1–10)"
log "Started: $(date)"
log ""

# ── Step 1: Ensure Docker daemon is running ──────────────────────────────────
log "## Step 1: Docker Daemon Check"
if ! "$DOCKER" info > /dev/null 2>&1; then
  log "Docker not running — starting OrbStack..."
  "$ORB" start 2>&1 | tee -a "$OUTPUT" || fail "Failed to start OrbStack"
  log "Waiting 30s for Docker daemon..."
  sleep 30
  if ! "$DOCKER" info > /dev/null 2>&1; then
    # Try opening OrbStack.app as fallback
    open -a OrbStack 2>/dev/null
    sleep 30
    "$DOCKER" info > /dev/null 2>&1 || fail "Docker daemon still not ready after 60s"
  fi
fi
log "Docker daemon: OK"
log ""

# ── Step 2: Check port 5432 is free ─────────────────────────────────────────
log "## Step 2: Port Check"
if lsof -i :5432 > /dev/null 2>&1; then
  log "WARNING: Port 5432 is in use. Attempting to stop any mcpfuzz-postgres container..."
  "$DOCKER" stop mcpfuzz-postgres 2>/dev/null || true
  "$DOCKER" rm   mcpfuzz-postgres 2>/dev/null || true
  sleep 3
  if lsof -i :5432 > /dev/null 2>&1; then
    fail "Port 5432 still in use by a non-Docker process. Cannot start PostgreSQL."
  fi
fi
log "Port 5432: free"
log ""

# ── Step 3: Start PostgreSQL container ──────────────────────────────────────
log "## Step 3: Starting PostgreSQL Container"
"$DOCKER" pull postgres:16 2>&1 | tee -a "$OUTPUT"
"$DOCKER" stop mcpfuzz-postgres 2>/dev/null || true
"$DOCKER" rm   mcpfuzz-postgres 2>/dev/null || true

"$DOCKER" run -d --name mcpfuzz-postgres \
  -e POSTGRES_PASSWORD=test \
  -e POSTGRES_DB=testdb \
  -p 5432:5432 \
  postgres:16 2>&1 | tee -a "$OUTPUT"

log "Waiting 20s for PostgreSQL to be ready..."
sleep 20

# Healthcheck with retries
PG_READY=0
for i in 1 2 3 4 5; do
  if "$DOCKER" exec mcpfuzz-postgres pg_isready -U postgres > /dev/null 2>&1; then
    PG_READY=1
    log "PostgreSQL is ready (attempt $i)."
    break
  fi
  log "Not ready yet, waiting 10s (attempt $i/5)..."
  sleep 10
done
[[ $PG_READY -eq 1 ]] || fail "PostgreSQL did not become ready after 70s"
log ""

# ── Scan helper ──────────────────────────────────────────────────────────────
scan_target() {
  local num="$1" name="$2" cmd="$3"
  shift 3
  local env_args=()
  for e in "$@"; do env_args+=(--env "$e"); done

  log ""
  log "---"
  log "## Target $num: $name"
  log "**Command:** \`$cmd\`"
  log "**Started:** $(date)"
  log ""
  log '```'
  "$MCPFUZZ" scan --server "$cmd" --transport stdio "${env_args[@]}" 2>&1 | tee -a "$OUTPUT" || true
  log '```'
  log "**Finished:** $(date)"
}

# ── Targets 1–10 ─────────────────────────────────────────────────────────────

scan_target 1 "@modelcontextprotocol/server-postgres" \
  "npx -y @modelcontextprotocol/server-postgres $PG_URL"

scan_target 2 "mcp-server-postgres (PyPI)" \
  "uvx mcp-server-postgres --connection-string $PG_URL"

scan_target 3 "bytebase/dbhub" \
  "npx -y @bytebase/dbhub --transport stdio --dsn \"$PG_URL2\""

scan_target 4 "postgres-mcp (PyPI)" \
  "uvx postgres-mcp --host localhost --port 5432 --user postgres --password test --dbname testdb"

scan_target 5 "mcp-postgres-full-access" \
  "npx -y mcp-postgres-full-access" \
  "POSTGRES_URL=$PG_URL"

scan_target 6 "mcp-postgres-server (antonorlov)" \
  "npx -y mcp-postgres-server" \
  "DATABASE_URL=$PG_URL"

scan_target 7 "mcp-postgres (npm, kristofer84)" \
  "npx -y mcp-postgres $PG_URL"

scan_target 8 "mcp-postgres (PyPI)" \
  "uvx mcp-postgres" \
  "DATABASE_URL=$PG_URL"

scan_target 9 "mcp-postgresql-ops (call518)" \
  "npx -y mcp-postgresql-ops" \
  "POSTGRES_HOST=localhost" \
  "POSTGRES_PORT=5432" \
  "POSTGRES_USER=postgres" \
  "POSTGRES_PASSWORD=test" \
  "POSTGRES_DB=testdb"

scan_target 10 "postgres-mcp-pro-plus (PyPI)" \
  "uvx postgres-mcp-pro-plus" \
  "DATABASE_URL=$PG_URL"

# ── Cleanup ──────────────────────────────────────────────────────────────────
log ""
log "## Cleanup"
"$DOCKER" stop mcpfuzz-postgres 2>/dev/null || true
"$DOCKER" rm   mcpfuzz-postgres 2>/dev/null || true
log "Container removed."

log ""
log "---"
log "## Batch 1 Complete"
log "Finished: $(date)"
log "Results: $OUTPUT"
