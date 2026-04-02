"""
SQL Injection Module
Targets: MCP tools that execute SQL queries or accept SQL-like filter parameters.
Method:
  Phase 1 — Error-based: inject SQL metacharacters and check response for DB error strings.
  Phase 2 — Boolean-blind: compare response to OR 1=1 (always-true) vs OR 1=2 (always-false).
             If the responses differ significantly, unsanitized SQL is likely being executed.
  Phase 3 — Time-based blind: inject SLEEP/pg_sleep/WAITFOR and measure latency delta.
CWE-89: Improper Neutralization of Special Elements used in an SQL Command
"""

import asyncio
import re
import time
from mcp import ClientSession

from .base import ScanModule
from ..models import Finding, FindingStatus, Severity


# ── Tool selection heuristics ─────────────────────────────────────────────────

SQL_TOOL_KEYWORDS = [
    "query", "search", "select", "find", "filter", "execute", "exec",
    "run", "fetch", "lookup", "get", "list", "scan", "retrieve",
    "read", "insert", "update", "delete", "upsert", "sql",
]

SQL_PARAM_NAMES = [
    "query", "sql", "statement", "filter", "where", "condition",
    "search", "expression", "q", "keyword", "term", "name",
    "id", "value", "input", "text", "content",
]

# Database backend indicators in tool names / descriptions — used for dialect selection
POSTGRES_INDICATORS = re.compile(r"postgres|postgresql|pg[_\s]|supabase|cockroach|timescale", re.I)
MYSQL_INDICATORS    = re.compile(r"mysql|mariadb|percona|aurora", re.I)
MSSQL_INDICATORS    = re.compile(r"mssql|sqlserver|sql server|sqlserv", re.I)
SQLITE_INDICATORS   = re.compile(r"sqlite", re.I)
ORACLE_INDICATORS   = re.compile(r"oracle|oracledb", re.I)

# ── SQL error signatures ──────────────────────────────────────────────────────
# Narrowly scoped — each pattern must be physically impossible to produce from
# a legitimate database query result (no generic "error", "invalid", etc.)

SQL_ERROR_PATTERNS = [
    # MySQL / MariaDB
    re.compile(r"You have an error in your SQL syntax", re.I),
    re.compile(r"mysql_fetch_(array|row|object|assoc)", re.I),
    re.compile(r"Warning: mysqli?_", re.I),
    re.compile(r"supplied argument is not a valid MySQL", re.I),
    re.compile(r"MySQL server version for the right syntax", re.I),
    re.compile(r"com\.mysql\.jdbc\.exceptions", re.I),

    # PostgreSQL
    re.compile(r'ERROR:\s+syntax error at or near "', re.I),
    re.compile(r"pg_query\(\):", re.I),
    re.compile(r"PSQLException", re.I),
    re.compile(r"org\.postgresql\.util\.PSQLException", re.I),
    re.compile(r"unterminated quoted string at or near", re.I),
    re.compile(r"invalid input syntax for type", re.I),

    # SQLite
    re.compile(r"SQLiteException", re.I),
    re.compile(r"sqlite3\.OperationalError", re.I),
    re.compile(r"unrecognized token: \"'\"", re.I),
    re.compile(r"near \"'\": syntax error", re.I),

    # MSSQL
    re.compile(r"Unclosed quotation mark after the character string", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"SqlException", re.I),
    re.compile(r"\[Microsoft\]\[ODBC SQL Server Driver\]", re.I),
    re.compile(r"Incorrect syntax near", re.I),

    # Oracle
    re.compile(r"ORA-\d{5}:", re.I),
    re.compile(r"oracle\.jdbc\.driver", re.I),

    # Generic SQLAlchemy / ORM
    re.compile(r"sqlalchemy\.exc\.", re.I),
    re.compile(r"OperationalError.*syntax error", re.I | re.S),
    re.compile(r"ProgrammingError.*syntax", re.I | re.S),
    re.compile(r"StatementError.*column", re.I | re.S),

    # Generic JDBC
    re.compile(r"java\.sql\.SQLException", re.I),
    re.compile(r"org\.hibernate\.exception", re.I),
]

# ── Payloads ──────────────────────────────────────────────────────────────────

# Error-based: bare quote / comment terminators that break SQL syntax
ERROR_PAYLOADS = [
    "'",
    "''",
    "' --",
    "' #",
    "\" --",
    "`;",
    "');",
    "' OR '",
]

# Boolean-blind pair: if OR 1=1 response ≠ OR 1=2 response, SQL is being executed
BOOL_TRUE_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "1 OR 1=1",
    "1' OR '1'='1",
    '" OR "1"="1',
    "admin' --",
    "') OR ('1'='1",
]
BOOL_FALSE_PAYLOADS = [
    "' OR '1'='2",
    "' OR 1=2 --",
    "1 OR 1=2",
    "1' OR '1'='2",
    '" OR "1"="2',
    "admin' AND '1'='2",
    "') OR ('1'='2",
]

# Time-based blind — dialect-specific sleep injections
TIME_PAYLOADS_MYSQL    = ["'; SELECT SLEEP(4); --", "1' AND SLEEP(4) AND '1'='1", "1 AND SLEEP(4)"]
TIME_PAYLOADS_POSTGRES = ["'; SELECT pg_sleep(4); --", "1'; SELECT pg_sleep(4);--", "1 AND 1=(SELECT 1 FROM pg_sleep(4))"]
TIME_PAYLOADS_MSSQL    = ["'; WAITFOR DELAY '0:0:4'; --", "1'; WAITFOR DELAY '0:0:4' --"]
TIME_PAYLOADS_SQLITE   = ["1 AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))))"]
TIME_PAYLOADS_GENERIC  = ["'; SELECT SLEEP(4); --", "'; SELECT pg_sleep(4); --"]

TIME_THRESHOLD = 3.5   # seconds — response ≥ this suggests sleep fired


def _extract_text(result) -> str:
    parts = []
    for item in result.content:
        if hasattr(item, "text"):
            parts.append(item.text)
        elif isinstance(item, dict) and "text" in item:
            parts.append(item["text"])
    return "\n".join(parts)


def _find_sql_error(text: str) -> str | None:
    """Return a short evidence snippet if a DB error pattern matches, else None."""
    for pattern in SQL_ERROR_PATTERNS:
        m = pattern.search(text)
        if m:
            start = max(0, m.start() - 20)
            end = min(len(text), m.end() + 150)
            return text[start:end].strip()
    return None


def _is_sql_tool(tool: dict) -> bool:
    """Heuristic: does this tool execute or accept SQL queries?"""
    name = tool.get("name", "").lower()
    desc = tool.get("description", "").lower()
    combined = name + " " + desc
    schema = tool.get("inputSchema", {})
    param_names = [k.lower() for k in schema.get("properties", {}).keys()]

    # Tool name or description strongly suggests SQL execution
    for kw in ["sql", "query", "execute", "select", "insert", "update", "delete",
                "upsert", "database", "table", "schema", "cursor", "records"]:
        if kw in combined:
            return True

    # Has a parameter whose name suggests it accepts SQL or a search expression
    return any(p in param_names for p in SQL_PARAM_NAMES)


def _get_injectable_params(tool: dict) -> list[str]:
    """Return parameters most likely to be passed to SQL execution."""
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {})

    # Priority 1: parameters named explicitly for SQL/queries
    high_priority = [
        name for name in properties
        if name.lower() in {"query", "sql", "statement", "filter", "where",
                             "condition", "expression", "search", "q"}
    ]
    if high_priority:
        return high_priority

    # Priority 2: string-type parameters with SQL-suggestive names
    medium_priority = [
        name for name, spec in properties.items()
        if name.lower() in SQL_PARAM_NAMES
        and (spec.get("type") == "string" or "type" not in spec)
    ]
    if medium_priority:
        return medium_priority

    # Priority 3: any string parameter (SQL tools sometimes name it generically)
    return [
        name for name, spec in properties.items()
        if spec.get("type") == "string" or "type" not in spec
    ][:2]  # Cap at 2 to avoid blasting every string param on large tools


def _detect_dialect(tool: dict, server_command: str) -> str:
    """Detect the probable SQL dialect from tool metadata and server command."""
    combined = (
        tool.get("name", "") + " " +
        tool.get("description", "") + " " +
        server_command
    ).lower()
    if POSTGRES_INDICATORS.search(combined):
        return "postgres"
    if MYSQL_INDICATORS.search(combined):
        return "mysql"
    if MSSQL_INDICATORS.search(combined):
        return "mssql"
    if SQLITE_INDICATORS.search(combined):
        return "sqlite"
    return "generic"


def _get_time_payloads(dialect: str) -> list[str]:
    return {
        "postgres": TIME_PAYLOADS_POSTGRES,
        "mysql":    TIME_PAYLOADS_MYSQL,
        "mssql":    TIME_PAYLOADS_MSSQL,
        "sqlite":   TIME_PAYLOADS_SQLITE,
    }.get(dialect, TIME_PAYLOADS_GENERIC)


def _responses_differ(resp_true: str, resp_false: str) -> bool:
    """
    Returns True if the boolean-true and boolean-false responses differ
    in a way that suggests the injected condition was evaluated by the DB.

    Criteria (require at least one):
    - Length difference > 5% of the longer response (not just 1-2 chars)
    - One response is empty/error while the other is not
    - Presence of data in one and absence in the other (heuristic: JSON array length)
    """
    if not resp_true and not resp_false:
        return False
    if not resp_true or not resp_false:
        # One produced output, the other didn't — significant difference
        return True

    len_t, len_f = len(resp_true), len(resp_false)
    max_len = max(len_t, len_f)
    # 20% threshold (was 5%) — reduces FPs from search engines / filesystem tools
    # that naturally return different-length error messages for different inputs.
    if max_len > 0 and abs(len_t - len_f) / max_len > 0.20:
        return True

    # Row-count heuristic: count commas in JSON-like responses
    # (more commas in true-response ≈ more rows returned)
    comma_t = resp_true.count(",")
    comma_f = resp_false.count(",")
    if abs(comma_t - comma_f) > 5:  # was 3 — avoid FPs on minor formatting differences
        return True

    return False


class SQLInjectionModule(ScanModule):
    module_id = "sql_injection"
    name = "SQL Injection"
    description = (
        "Tests MCP database tools for SQL injection (CWE-89) via error-based, "
        "boolean-blind, and time-based blind techniques across MySQL, PostgreSQL, "
        "SQLite, and MSSQL dialects"
    )

    async def run(self, session: ClientSession, tools: list[dict]) -> list[Finding]:
        findings: list[Finding] = []

        for tool in tools:
            if not _is_sql_tool(tool):
                continue

            tool_name = tool["name"]
            injectable_params = _get_injectable_params(tool)
            if not injectable_params:
                continue

            dialect = _detect_dialect(tool, self.server_command)
            schema = tool.get("inputSchema", {})
            all_params = list(schema.get("properties", {}).keys())

            for param in injectable_params:
                confirmed = False

                # ── Phase 1: Error-based detection ───────────────────────────
                for payload in ERROR_PAYLOADS:
                    if confirmed:
                        break
                    try:
                        args = {p: "test" for p in all_params}
                        args[param] = payload
                        result = await asyncio.wait_for(
                            session.call_tool(tool_name, arguments=args),
                            timeout=12,
                        )
                        response_text = _extract_text(result)
                        evidence = _find_sql_error(response_text)

                        if evidence:
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"SQL Injection in '{tool_name}' via '{param}' (Error-Based)",
                                severity=Severity.CRITICAL,
                                status=FindingStatus.CONFIRMED,
                                cvss_score=9.8,
                                description=(
                                    f"The MCP tool '{tool_name}' returned a database error message "
                                    f"when the '{param}' parameter was set to {payload!r}. "
                                    f"The raw SQL error in the response confirms that user input is "
                                    f"being interpolated directly into SQL without parameterization."
                                ),
                                tool_name=tool_name,
                                payload_used=f"{param}={payload!r}",
                                payload_args=args,
                                evidence=f"DB error in response: {evidence}",
                                remediation=(
                                    "Use parameterized queries (prepared statements) for all database "
                                    "operations. Never interpolate tool parameters directly into SQL "
                                    "strings. In Python: cursor.execute(sql, (param,)); "
                                    "In Node.js: pool.query(sql, [param])."
                                ),
                                raw_response=response_text[:1000],
                                cwe_id="CWE-89",
                            ))
                            confirmed = True
                    except asyncio.TimeoutError:
                        pass
                    except Exception:
                        pass

                if confirmed:
                    continue

                # ── Phase 2: Boolean-blind detection ─────────────────────────
                # Establish a baseline response first with a benign value
                try:
                    baseline_args = {p: "test" for p in all_params}
                    baseline_args[param] = "testvalue_mcpfuzz_baseline"
                    baseline_result = await asyncio.wait_for(
                        session.call_tool(tool_name, arguments=baseline_args),
                        timeout=12,
                    )
                    baseline_text = _extract_text(baseline_result)
                except Exception:
                    baseline_text = ""

                for true_payload, false_payload in zip(BOOL_TRUE_PAYLOADS, BOOL_FALSE_PAYLOADS):
                    if confirmed:
                        break
                    try:
                        true_args = {p: "test" for p in all_params}
                        true_args[param] = true_payload
                        true_result = await asyncio.wait_for(
                            session.call_tool(tool_name, arguments=true_args),
                            timeout=12,
                        )
                        resp_true = _extract_text(true_result)

                        false_args = {p: "test" for p in all_params}
                        false_args[param] = false_payload
                        false_result = await asyncio.wait_for(
                            session.call_tool(tool_name, arguments=false_args),
                            timeout=12,
                        )
                        resp_false = _extract_text(false_result)

                        # Responses must differ from each other AND from baseline
                        # to rule out: (a) fixed error, (b) fixed success with no
                        # condition evaluation, (c) baseline == true (normal behaviour)
                        if (
                            _responses_differ(resp_true, resp_false)
                            and resp_true != baseline_text
                        ):
                            evidence_snippet = (
                                f"OR 1=1 returned {len(resp_true)} chars; "
                                f"OR 1=2 returned {len(resp_false)} chars; "
                                f"baseline returned {len(baseline_text)} chars"
                            )
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"Possible SQL Injection in '{tool_name}' via '{param}' (Boolean-Blind)",
                                severity=Severity.HIGH,
                                status=FindingStatus.POTENTIAL,
                                cvss_score=7.5,
                                description=(
                                    f"The MCP tool '{tool_name}' produces measurably different "
                                    f"responses for always-true ({true_payload!r}) vs always-false "
                                    f"({false_payload!r}) conditions injected via the '{param}' "
                                    f"parameter. This is consistent with boolean-blind SQL injection "
                                    f"but also with search tools returning different result sets for "
                                    f"different query strings. Manual confirmation required."
                                ),
                                tool_name=tool_name,
                                payload_used=f"{param}={true_payload!r} vs {param}={false_payload!r}",
                                payload_args=true_args,
                                evidence=evidence_snippet,
                                remediation=(
                                    "Use parameterized queries (prepared statements) for all database "
                                    "operations. Never concatenate or format user input into SQL strings."
                                ),
                                cwe_id="CWE-89",
                            ))
                            confirmed = True

                    except asyncio.TimeoutError:
                        pass
                    except Exception:
                        pass

                if confirmed:
                    continue

                # ── Phase 3: Time-based blind detection ──────────────────────
                time_payloads = _get_time_payloads(dialect)
                for payload in time_payloads:
                    if confirmed:
                        break
                    try:
                        args = {p: "test" for p in all_params}
                        args[param] = payload

                        t0 = time.monotonic()
                        await asyncio.wait_for(
                            session.call_tool(tool_name, arguments=args),
                            timeout=TIME_THRESHOLD + 4,
                        )
                        elapsed = time.monotonic() - t0

                        if elapsed >= TIME_THRESHOLD:
                            findings.append(Finding(
                                module_id=self.module_id,
                                title=f"SQL Injection in '{tool_name}' via '{param}' (Time-Based Blind, {dialect})",
                                severity=Severity.HIGH,
                                status=FindingStatus.CONFIRMED,
                                cvss_score=8.1,
                                description=(
                                    f"The MCP tool '{tool_name}' took {elapsed:.1f}s to respond when "
                                    f"the '{param}' parameter contained a {dialect} time-delay SQL "
                                    f"injection payload ({payload!r}). This is consistent with the "
                                    f"database executing the injected SLEEP/pg_sleep/WAITFOR statement."
                                ),
                                tool_name=tool_name,
                                payload_used=f"{param}={payload!r}",
                                payload_args=args,
                                evidence=f"Response time {elapsed:.1f}s ≥ {TIME_THRESHOLD}s threshold — sleep likely executed",
                                remediation=(
                                    "Use parameterized queries for all database operations. "
                                    "Disable stacked queries if the database driver supports it."
                                ),
                                cwe_id="CWE-89",
                            ))
                            confirmed = True
                    except asyncio.TimeoutError:
                        # Hard timeout at threshold+4 is also evidence of sleep
                        elapsed = TIME_THRESHOLD + 4
                        findings.append(Finding(
                            module_id=self.module_id,
                            title=f"SQL Injection in '{tool_name}' via '{param}' (Time-Based Blind Timeout, {dialect})",
                            severity=Severity.HIGH,
                            status=FindingStatus.CONFIRMED,
                            cvss_score=8.1,
                            description=(
                                f"The tool '{tool_name}' timed out (>{TIME_THRESHOLD + 4}s) when "
                                f"'{param}' contained a {dialect} time-delay payload. "
                                f"The database is likely executing the injected sleep statement."
                            ),
                            tool_name=tool_name,
                            payload_used=f"{param}={payload!r}",
                            payload_args=args,
                            evidence=f"Request timed out — sleep/waitfor likely blocked the query thread",
                            remediation=(
                                "Use parameterized queries for all database operations. "
                                "Disable stacked queries if the database driver supports it."
                            ),
                            cwe_id="CWE-89",
                        ))
                        confirmed = True
                    except Exception:
                        pass

        return findings
