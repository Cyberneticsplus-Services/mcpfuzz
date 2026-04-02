#!/bin/bash
# MCPFuzz Docker Batch 2 — Targets 11–20 (Redis 11–15, MongoDB 16–20)
# Scheduled: 2:30 AM IST 2026-03-30

# ── Absolute paths (cron runs with minimal PATH) ─────────────────────────────
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/Users/agentprime/.local/bin:/usr/local/bin:/usr/bin:/bin"

MCPFUZZ="/opt/homebrew/bin/mcpfuzz"
DOCKER="/usr/local/bin/docker"
ORB="/opt/homebrew/bin/orb"
RESULTS_DIR="/Users/agentprime/Desktop/mcpfuzz/docker-results"
OUTPUT="$RESULTS_DIR/batch2-$(date +%Y%m%d-%H%M).md"

mkdir -p "$RESULTS_DIR"

log() { echo "$1" | tee -a "$OUTPUT"; }
fail() { log "FATAL: $1"; exit 1; }

log "# MCPFuzz Docker Batch 2 — Redis (11–15) + MongoDB (16–20)"
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
    open -a OrbStack 2>/dev/null
    sleep 30
    "$DOCKER" info > /dev/null 2>&1 || fail "Docker daemon still not ready after 60s"
  fi
fi
log "Docker daemon: OK"
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

# ════════════════════════════════════════════════════════════════════════════
# REDIS — Targets 11–15
# ════════════════════════════════════════════════════════════════════════════
log "---"
log "# Redis Targets (11–15)"
log ""

# Port check
if lsof -i :6379 > /dev/null 2>&1; then
  log "WARNING: Port 6379 in use. Stopping any mcpfuzz-redis container..."
  "$DOCKER" stop mcpfuzz-redis 2>/dev/null || true
  "$DOCKER" rm   mcpfuzz-redis 2>/dev/null || true
  sleep 3
  lsof -i :6379 > /dev/null 2>&1 && fail "Port 6379 still in use. Cannot start Redis."
fi

"$DOCKER" pull redis:7 2>&1 | tee -a "$OUTPUT"
"$DOCKER" stop mcpfuzz-redis 2>/dev/null || true
"$DOCKER" rm   mcpfuzz-redis 2>/dev/null || true
"$DOCKER" run -d --name mcpfuzz-redis -p 6379:6379 redis:7 2>&1 | tee -a "$OUTPUT"

log "Waiting 10s for Redis..."
sleep 10

# Healthcheck
REDIS_READY=0
for i in 1 2 3; do
  if "$DOCKER" exec mcpfuzz-redis redis-cli ping 2>/dev/null | grep -q PONG; then
    REDIS_READY=1
    log "Redis is ready (attempt $i)."
    break
  fi
  log "Redis not ready yet, waiting 5s (attempt $i/3)..."
  sleep 5
done
[[ $REDIS_READY -eq 1 ]] || fail "Redis did not become ready"

scan_target 11 "redis-mcp-server (PyPI, Official Redis Inc)" \
  "uvx redis-mcp-server" \
  "REDIS_HOST=localhost" \
  "REDIS_PORT=6379"

scan_target 12 "@modelcontextprotocol/server-redis" \
  "npx -y @modelcontextprotocol/server-redis redis://localhost:6379"

scan_target 13 "mcp-redis-diagnostics" \
  "npx -y mcp-redis-diagnostics" \
  "REDIS_URL=redis://localhost:6379"

scan_target 14 "@liangshanli/mcp-server-redis" \
  "npx -y @liangshanli/mcp-server-redis" \
  "REDIS_HOST=localhost" \
  "REDIS_PORT=6379"

scan_target 15 "mcp-server-redis (PyPI)" \
  "uvx mcp-server-redis" \
  "REDIS_HOST=localhost" \
  "REDIS_PORT=6379" \
  "REDIS_DB=0" \
  "REDIS_PASSWORD="

"$DOCKER" stop mcpfuzz-redis 2>/dev/null || true
"$DOCKER" rm   mcpfuzz-redis 2>/dev/null || true
log "Redis container removed."

# ════════════════════════════════════════════════════════════════════════════
# MONGODB — Targets 16–20
# ════════════════════════════════════════════════════════════════════════════
log ""
log "---"
log "# MongoDB Targets (16–20)"
log ""

# Port check — existing Atlas containers use mapped ports (32768/32769), not 27017
if lsof -i :27017 > /dev/null 2>&1; then
  log "WARNING: Port 27017 in use. Stopping any mcpfuzz-mongo container..."
  "$DOCKER" stop mcpfuzz-mongo 2>/dev/null || true
  "$DOCKER" rm   mcpfuzz-mongo 2>/dev/null || true
  sleep 3
  lsof -i :27017 > /dev/null 2>&1 && fail "Port 27017 still in use. Cannot start MongoDB."
fi

"$DOCKER" pull mongo:7 2>&1 | tee -a "$OUTPUT"
"$DOCKER" stop mcpfuzz-mongo 2>/dev/null || true
"$DOCKER" rm   mcpfuzz-mongo 2>/dev/null || true
"$DOCKER" run -d --name mcpfuzz-mongo -p 27017:27017 mongo:7 2>&1 | tee -a "$OUTPUT"

log "Waiting 20s for MongoDB..."
sleep 20

# Healthcheck
MONGO_READY=0
for i in 1 2 3; do
  if "$DOCKER" exec mcpfuzz-mongo mongosh --eval "db.runCommand({ping:1})" --quiet > /dev/null 2>&1; then
    MONGO_READY=1
    log "MongoDB is ready (attempt $i)."
    break
  fi
  log "MongoDB not ready yet, waiting 10s (attempt $i/3)..."
  sleep 10
done
[[ $MONGO_READY -eq 1 ]] || fail "MongoDB did not become ready"

scan_target 16 "mongodb-mcp-server (Official MongoDB)" \
  "npx -y mongodb-mcp-server --connectionString mongodb://localhost:27017"

scan_target 17 "mcp-mongo-server (kiliczsh)" \
  "npx -y mcp-mongo-server mongodb://localhost:27017"

scan_target 18 "mongodb-lens (furey)" \
  "npx -y mongodb-lens" \
  "MONGODB_URI=mongodb://localhost:27017"

scan_target 19 "mongo-mcp (PyPI)" \
  "uvx mongo-mcp" \
  "MONGO_URI=mongodb://localhost:27017"

scan_target 20 "@florentine-ai/mcp" \
  "npx -y @florentine-ai/mcp" \
  "MONGO_URI=mongodb://localhost:27017"

"$DOCKER" stop mcpfuzz-mongo 2>/dev/null || true
"$DOCKER" rm   mcpfuzz-mongo 2>/dev/null || true
log "MongoDB container removed."

log ""
log "---"
log "## Batch 2 Complete"
log "Finished: $(date)"
log "Results: $OUTPUT"
