# Installation

## Requirements

- Python **3.11 or later**
- `npx` or `uvx` if you want to scan Node.js or Python MCP servers without installing them yourself
- Internet access for OOB (Out-of-Band) SSRF detection (optional — MCPFuzz starts a local callback server automatically)

---

## Option 1 — pip (recommended)

```bash
pip install mcpfuzz
```

Verify the install:

```bash
mcpfuzz --version
```

### Optional extras

```bash
# Enable LLM-judge for tool poisoning detection (uses Claude Haiku)
pip install 'mcpfuzz[llm]'

# Use Ollama (local or cloud) as the LLM judge instead of Anthropic
pip install 'mcpfuzz[ollama]'

# Use OpenAI as the LLM judge
pip install 'mcpfuzz[openai]'

# All LLM providers
pip install 'mcpfuzz[all]'

# Enable terminal screenshot generation for POC output
pip install mcpfuzz Pillow
```

---

## Option 2 — From source

Use this if you want to run the latest code or contribute changes.

```bash
git clone https://github.com/Cyberneticsplus-Services/mcpfuzz.git
cd mcpfuzz
pip install -e .
```

For development (includes all optional dependencies):

```bash
pip install -e '.[all]'
```

Verify:

```bash
mcpfuzz --version
mcpfuzz list-modules
```

---

## Option 3 — uvx (no install)

If you have [uv](https://github.com/astral-sh/uv) installed you can run MCPFuzz without installing it:

```bash
uvx mcpfuzz scan --server "npx @modelcontextprotocol/server-filesystem /tmp"
```

---

## Troubleshooting

**`command not found: mcpfuzz`**

The `mcpfuzz` binary was installed into a directory that's not on your `$PATH`. Common fixes:

```bash
# macOS / Linux — add user scripts to PATH
export PATH="$HOME/.local/bin:$PATH"

# or install into your virtual environment
python -m venv .venv && source .venv/bin/activate && pip install mcpfuzz
```

**`No module named 'mcpfuzz'`**

You have multiple Python installations. Make sure you install into the same Python that the `mcpfuzz` binary uses:

```bash
which python3
# /opt/homebrew/bin/python3

python3 -m pip install mcpfuzz
```

**`ModuleNotFoundError: mcp`**

The `mcp` Python SDK is a required dependency — it should install automatically. If it didn't:

```bash
pip install 'mcp>=1.23.0'
```
