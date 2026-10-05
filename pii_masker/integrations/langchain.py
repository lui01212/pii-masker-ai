"""
LangChain & LLM framework integration for pii-masker-ai.
Provides transparent round-trip de-identification for prompts and chat models.
Works with zero external dependencies (gracefully enhances if langchain is installed).
"""

import copy
from typing import Any, Dict, Iterator, List, Optional, Union
from pii_masker.core import PIIMasker, MaskResult, MaskMode


try:
    from langchain_core.callbacks.base import BaseCallbackHandler  # type: ignore
except ImportError:
    class BaseCallbackHandler:  # type: ignore
        """Fallback duck-type handler if langchain-core is not installed."""
        pass


def _iter_strings(value: Any) -> Iterator[str]:
    """Yield every string inside message content (plain text or a list of content blocks)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def _copy_with_content(message: Any, content: Any) -> Any:
    """Copy a message object with new content; the caller's object is never modified."""
    model_copy = getattr(message, "model_copy", None)
    if callable(model_copy):
        # pydantic v2 models (langchain-core >= 0.3) keep every other field
        return model_copy(update={"content": content})
    clone = copy.copy(message)
    clone.content = content
    return clone


class PIILangChainCallback(BaseCallbackHandler):
    """
    LangChain Callback Handler that monitors and logs PII detections
    during LLM chain and agent executions.

    With raise_on_pii=True the handler sets raise_error, so LangChain propagates the
    exception and the call is blocked instead of the error being logged and ignored.
    """

    def __init__(
        self,
        masker: Optional[PIIMasker] = None,
        raise_on_pii: bool = False,
        mode: str = MaskMode.REVERSIBLE,
    ):
        super().__init__()
        self.masker = masker or PIIMasker()
        self.raise_on_pii = raise_on_pii
        # LangChain swallows handler exceptions unless the handler sets raise_error
        self.raise_error = raise_on_pii
        self.mode = mode
        self.detected_entities: List[Dict[str, Any]] = []
        # Mapping for the most recent request only (replaced on every callback, not thread-safe)
        self.last_mapping: Dict[str, str] = {}

    def _inspect(self, text: str, mapping: Dict[str, str], what: str) -> None:
        res = self.masker.mask(text, mode=self.mode, mapping=mapping)
        if res.has_pii:
            self.detected_entities.extend(
                [{"category": e.category, "text": e.original} for e in res.entities]
            )
            mapping.update(res.mapping)
            if self.raise_on_pii:
                raise ValueError(
                    f"[PIISecurityException] Outgoing {what} contains {res.entity_count} sensitive PII entities!"
                )

    def on_llm_start(
        self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any
    ) -> None:
        """Inspects outgoing prompts before they reach the provider API."""
        mapping: Dict[str, str] = {}
        self.last_mapping = mapping
        for p in prompts:
            self._inspect(p, mapping, "prompt")

    def on_chat_model_start(
        self, serialized: Dict[str, Any], messages: List[List[Any]], **kwargs: Any
    ) -> None:
        """Inspects outgoing chat message lists (text content and content blocks)."""
        mapping: Dict[str, str] = {}
        self.last_mapping = mapping
        for msg_list in messages:
            for msg in msg_list:
                for text in _iter_strings(getattr(msg, "content", "")):
                    self._inspect(text, mapping, "message")


class PIIChatWrapper:
    """
    Transparent Wrapper for any Chat Model or Callable LLM.

    Automatically:
    1. Masks all sensitive PII from incoming user/system prompts.
    2. Sends sanitized prompts to LLM (Anthropic Claude, OpenAI, Ollama, etc.).
    3. Unmasks the LLM response text, restoring original customer names/IDs seamlessly.

    Inputs: strings, message objects (content as text or content blocks), (role, text) tuples,
    dicts (values masked recursively), lists of these, and prompt values with to_messages().
    Anything else raises TypeError instead of being sent unmasked.

    Each invoke() uses its own mapping, so one wrapper can serve several users. last_mapping
    holds the mapping of the most recent call for inspection only: concurrent calls overwrite
    it (it is not thread-safe), and unmasking never reads it.

    Example:
    >>> from langchain_anthropic import ChatAnthropic
    >>> from pii_masker.integrations import PIIChatWrapper
    >>>
    >>> base_llm = ChatAnthropic(model="claude-3-5-sonnet-20241022")
    >>> shielded_llm = PIIChatWrapper(base_llm)
    >>> response = shielded_llm.invoke("Send email to alice@company.com with bill $500")
    """

    def __init__(
        self,
        llm: Any,
        masker: Optional[PIIMasker] = None,
        mode: str = MaskMode.REVERSIBLE,
        unmask_response: bool = True,
    ):
        self.llm = llm
        self.masker = masker or PIIMasker()
        self.mode = mode
        self.unmask_response = unmask_response
        self.last_mapping: Dict[str, str] = {}

    def _mask_text(self, text: str, mapping: Dict[str, str]) -> str:
        res = self.masker.mask(text, mode=self.mode, mapping=mapping)
        mapping.update(res.mapping)
        return res.masked_text

    def _mask_value(self, value: Any, mapping: Dict[str, str]) -> Any:
        if isinstance(value, str):
            return self._mask_text(value, mapping)
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            # A number can be PII too (a card number as int): replace it only if masking changes it
            text = str(value)
            masked = self._mask_text(text, mapping)
            return masked if masked != text else value
        if isinstance(value, dict):
            return {key: self._mask_value(item, mapping) for key, item in value.items()}
        if isinstance(value, list):
            return [self._mask_value(item, mapping) for item in value]
        if isinstance(value, tuple):
            # e.g. ("human", "my mail is ...")
            return tuple(self._mask_value(item, mapping) for item in value)
        to_messages = getattr(value, "to_messages", None)
        if callable(to_messages):
            # PromptValue (ChatPromptValue, StringPromptValue): send its messages, masked
            return self._mask_value(list(to_messages()), mapping)
        if hasattr(value, "content"):
            # LangChain message object (HumanMessage, SystemMessage, AIMessage, ToolMessage)
            return _copy_with_content(value, self._mask_value(value.content, mapping))
        raise TypeError(
            f"PIIChatWrapper cannot mask input of type {type(value).__name__}; "
            "pass strings, messages, (role, text) tuples, dicts, lists or prompt values"
        )

    def _mask_input(self, input_val: Any, mapping: Optional[Dict[str, str]] = None) -> Any:
        """Mask strings, messages and containers recursively into a new object."""
        if mapping is None:
            mapping = {}
            self.last_mapping = mapping
        return self._mask_value(input_val, mapping)

    def _unmask_value(self, value: Any, mapping: Dict[str, str]) -> Any:
        if isinstance(value, str):
            return self.masker.unmask(value, mapping)
        if isinstance(value, dict):
            return {key: self._unmask_value(item, mapping) for key, item in value.items()}
        if isinstance(value, list):
            return [self._unmask_value(item, mapping) for item in value]
        if isinstance(value, tuple):
            return tuple(self._unmask_value(item, mapping) for item in value)
        content = getattr(value, "content", None)
        if isinstance(content, (str, list)):
            return _copy_with_content(value, self._unmask_value(content, mapping))
        return value

    def _unmask_output(self, output_val: Any, mapping: Optional[Dict[str, str]] = None) -> Any:
        """Restore masked placeholders in response."""
        if mapping is None:
            mapping = self.last_mapping
        if not self.unmask_response or not mapping:
            return output_val
        return self._unmask_value(output_val, mapping)

    def invoke(self, input_val: Any, *args: Any, **kwargs: Any) -> Any:
        """Invoke wrapped model with sanitized input and unmasked output."""
        mapping: Dict[str, str] = {}
        self.last_mapping = mapping
        sanitized_input = self._mask_input(input_val, mapping)

        if hasattr(self.llm, "invoke"):
            output = self.llm.invoke(sanitized_input, *args, **kwargs)
        elif callable(self.llm):
            output = self.llm(sanitized_input, *args, **kwargs)
        else:
            raise TypeError(f"Wrapped LLM {type(self.llm)} is neither callable nor implements invoke()")

        return self._unmask_output(output, mapping)

    def __call__(self, input_val: Any, *args: Any, **kwargs: Any) -> Any:
        return self.invoke(input_val, *args, **kwargs)
