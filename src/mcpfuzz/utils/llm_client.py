"""
Provider-agnostic LLM client for the MCPFuzz tool-poisoning LLM judge.

Supports three providers:
  - anthropic : Claude models via anthropic SDK   (pip install 'mcpfuzz[llm]')
  - ollama    : Ollama via native ollama SDK       (pip install 'mcpfuzz[ollama]')
                Cloud models (minimax-m2.5:cloud, qwen3.5:cloud etc.) run through
                the LOCAL Ollama daemon (localhost:11434) — Ollama routes inference
                to cloud GPUs transparently. No API key needed; auth is via
                `ollama signin`. Direct Ollama Cloud API (https://ollama.com +
                OLLAMA_API_KEY) is also supported via --llm-key.
  - openai    : OpenAI models via openai SDK       (pip install 'mcpfuzz[openai]')

Usage — Ollama cloud model via local daemon (recommended, no API key):
    client = LLMJudgeClient(provider="ollama", model="minimax-m2.5:cloud")
    text = client.judge(system_prompt, user_prompt)

Usage — direct Ollama Cloud API (requires OLLAMA_API_KEY):
    client = LLMJudgeClient(provider="ollama", api_key="sk-...", model="qwen3.5:cloud")
    text = client.judge(system_prompt, user_prompt)
"""

from __future__ import annotations


class LLMJudgeClient:
    """Wraps Anthropic, Ollama (cloud + local), and OpenAI behind one interface."""

    ANTHROPIC = "anthropic"
    OLLAMA    = "ollama"
    OPENAI    = "openai"

    # Cloud Ollama host — used automatically when an OLLAMA_API_KEY is supplied
    OLLAMA_CLOUD_HOST = "https://ollama.com"
    OLLAMA_LOCAL_HOST = "http://localhost:11434"

    # Default models per provider.
    # Ollama default is minimax-m2.5:cloud — same model OpenClaw uses, runs via
    # local Ollama daemon which routes to cloud GPUs automatically.
    DEFAULT_MODELS: dict[str, str] = {
        "anthropic":    "claude-haiku-4-5-20251001",
        "ollama":       "minimax-m2.5:cloud",
        "openai":       "gpt-4o-mini",
    }

    def __init__(
        self,
        provider: str,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
    ) -> None:
        if provider not in (self.ANTHROPIC, self.OLLAMA, self.OPENAI):
            raise ValueError(
                f"Unknown LLM provider {provider!r}. "
                f"Valid options: anthropic, ollama, openai"
            )

        self.provider = provider

        if provider == self.ANTHROPIC:
            try:
                import anthropic  # type: ignore
            except ImportError:
                raise ImportError(
                    "anthropic package not installed. "
                    "Run: pip install 'mcpfuzz[llm]'  or  pip install anthropic"
                )
            self.model = model or self.DEFAULT_MODELS["anthropic"]
            self._client = anthropic.Anthropic(api_key=api_key)

        elif provider == self.OLLAMA:
            try:
                from ollama import Client  # type: ignore
            except ImportError:
                raise ImportError(
                    "ollama package not installed. "
                    "Run: pip install 'mcpfuzz[ollama]'  or  pip install ollama"
                )
            self.model = model or self.DEFAULT_MODELS["ollama"]
            # Default: local Ollama daemon — cloud models (minimax-m2.5:cloud,
            # qwen3.5:cloud etc.) are routed to cloud GPUs automatically by Ollama.
            # Direct Ollama Cloud API: supply api_key → host switches to ollama.com.
            host = base_url or (self.OLLAMA_CLOUD_HOST if api_key else self.OLLAMA_LOCAL_HOST)
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            self._client = Client(host=host, headers=headers)

        else:  # openai
            try:
                import openai  # type: ignore
            except ImportError:
                raise ImportError(
                    "openai package not installed. "
                    "Run: pip install 'mcpfuzz[openai]'  or  pip install openai"
                )
            self.model = model or self.DEFAULT_MODELS["openai"]
            self._client = openai.OpenAI(
                api_key=api_key,
                **({"base_url": base_url} if base_url else {}),
            )

    def judge(self, system_prompt: str, user_prompt: str, max_tokens: int = 256) -> str:
        """
        Send a system + user prompt pair and return the model's text response.
        Raises on API / network errors — callers should catch Exception and skip.
        """
        if self.provider == self.ANTHROPIC:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return response.content[0].text.strip()

        elif self.provider == self.OLLAMA:
            response = self._client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return response.message.content.strip()

        else:  # openai
            response = self._client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return response.choices[0].message.content.strip()
