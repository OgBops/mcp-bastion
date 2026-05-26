"""Prompt-injection classifier.

Optional check that scores tool descriptions and tool outputs for prompt
injection. Wraps a HuggingFace model (default: protectai/deberta-v3-base-prompt-
injection-v2) behind a tiny synchronous interface.

Lazy-loaded: the model only downloads + initializes when first .score() is
called. Importing this module costs nothing.

Cost: model is ~750MB, ~50-100ms inference per call on CPU. Wire it sparingly
— v0.2 only scores tool descriptions on tools/list responses, not every frame.
"""

from __future__ import annotations

import sys
from threading import Lock
from typing import Any


DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"


class _LazyClassifier:
    """Singleton-ish wrapper. Loads the pipeline on first use."""

    def __init__(self, model_name: str = DEFAULT_MODEL) -> None:
        self.model_name = model_name
        self._pipe: Any = None
        self._lock = Lock()
        self._import_failed = False

    def _ensure_loaded(self) -> bool:
        if self._pipe is not None:
            return True
        if self._import_failed:
            return False
        with self._lock:
            if self._pipe is not None:
                return True
            try:
                from transformers import pipeline  # type: ignore[import-not-found]
            except ImportError:
                sys.stderr.write(
                    "[mcp-bastion] classifier requested but `transformers` not installed. "
                    "Install with: pip install 'mcp-bastion[classifier]'\n"
                )
                self._import_failed = True
                return False
            try:
                self._pipe = pipeline(
                    "text-classification",
                    model=self.model_name,
                    truncation=True,
                    max_length=512,
                )
            except Exception as e:  # pragma: no cover
                sys.stderr.write(f"[mcp-bastion] classifier load failed: {e}\n")
                self._import_failed = True
                return False
            return True

    def score(self, text: str) -> float | None:
        """Return injection probability in [0, 1], or None if unavailable.

        For protectai/deberta-v3-base-prompt-injection-v2 the labels are
        SAFE / INJECTION; we surface P(INJECTION).
        """
        if not text or not text.strip():
            return 0.0
        if not self._ensure_loaded():
            return None
        try:
            results = self._pipe(text)
        except Exception as e:  # pragma: no cover
            sys.stderr.write(f"[mcp-bastion] classifier inference error: {e}\n")
            return None
        if not results:
            return 0.0
        first = results[0] if isinstance(results, list) else results
        label = str(first.get("label", "")).upper()
        score = float(first.get("score", 0.0))
        if "INJECT" in label:
            return score
        return 1.0 - score


_INSTANCE: _LazyClassifier | None = None
_INSTANCE_LOCK = Lock()


def get_classifier(model_name: str = DEFAULT_MODEL) -> _LazyClassifier:
    """Get the process-wide classifier singleton."""
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is None or _INSTANCE.model_name != model_name:
            _INSTANCE = _LazyClassifier(model_name)
        return _INSTANCE
