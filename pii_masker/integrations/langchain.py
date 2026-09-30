"""
LangChain & LLM framework integration for pii-masker-ai.
Provides transparent round-trip de-identification for prompts and chat models.
Works with zero external dependencies (gracefully enhances if langchain is installed).
"""

from typing import Any, Dict, List, Optional, Union
from pii_masker.core import PIIMasker, MaskResult, MaskMode


try:
    from langchain_core.callbacks.base import BaseCallbackHandler  # type: ignore
except ImportError:
    class BaseCallbackHandler:  # type: ignore
        """Fallback duck-type handler if langchain-core is not installed."""
        pass


class PIILangChainCallback(BaseCallbackHandler):
    """
    LangChain Callback Handler that monitors and logs PII detections
    during LLM chain and agent executions.
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
        self.mode = mode
        self.detected_entities: List[Dict[str, Any]] = []
        self.last_mapping: Dict[str, str] = {}

    def on_llm_start(
        self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any
    ) -> None:
        """Inspects outgoing prompts before they reach the provider API."""
        for p in prompts:
            res = self.masker.mask(p, mode=self.mode)
            if res.has_pii:
                self.detected_entities.extend(
                    [{"category": e.category, "text": e.original} for e in res.entities]
                )
                self.last_mapping.update(res.mapping)
                if self.raise_on_pii:
                    raise ValueError(
                        f"[PIISecurityException] Outgoing prompt contains {res.entity_count} sensitive PII entities!"
                    )

    def on_chat_model_start(
        self, serialized: Dict[str, Any], messages: List[List[Any]], **kwargs: Any
    ) -> None:
        """Inspects outgoing chat message lists."""
        for msg_list in messages:
            for msg in msg_list:
                content = getattr(msg, "content", "")
                if isinstance(content, str):
                    res = self.masker.mask(content, mode=self.mode)
                    if res.has_pii:
                        self.detected_entities.extend(
                            [{"category": e.category, "text": e.original} for e in res.entities]
                        )
                        self.last_mapping.update(res.mapping)
                        if self.raise_on_pii:
                            raise ValueError(
                                f"[PIISecurityException] Outgoing message contains {res.entity_count} sensitive PII entities!"
                            )


class PIIChatWrapper:
    """
    Transparent Wrapper for any Chat Model or Callable LLM.
    
    Automatically:
    1. Masks all sensitive PII from incoming user/system prompts.
    2. Sends sanitized prompts to LLM (Anthropic Claude, OpenAI, Ollama, etc.).
    3. Unmasks the LLM response text, restoring original customer names/IDs seamlessly.
    
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

    def _mask_input(self, input_val: Any) -> Any:
        """Mask string or message objects recursively."""
        if isinstance(input_val, str):
            res = self.masker.mask(input_val, mode=self.mode)
            self.last_mapping.update(res.mapping)
            return res.masked_text

        # If list of messages or dictionaries
        if isinstance(input_val, list):
            new_list = []
            for item in input_val:
                if isinstance(item, str):
                    res = self.masker.mask(item, mode=self.mode)
                    self.last_mapping.update(res.mapping)
                    new_list.append(res.masked_text)
                elif hasattr(item, "content") and isinstance(item.content, str):
                    # LangChain message object (HumanMessage, SystemMessage, AIMessage)
                    res = self.masker.mask(item.content, mode=self.mode)
                    self.last_mapping.update(res.mapping)
                    # Clone message with masked content
                    item_type = type(item)
                    try:
                        new_msg = item_type(content=res.masked_text)
                    except Exception:
                        new_msg = item
                        new_msg.content = res.masked_text
                    new_list.append(new_msg)
                elif isinstance(item, dict) and "content" in item and isinstance(item["content"], str):
                    d = dict(item)
                    res = self.masker.mask(d["content"], mode=self.mode)
                    self.last_mapping.update(res.mapping)
                    d["content"] = res.masked_text
                    new_list.append(d)
                else:
                    new_list.append(item)
            return new_list

        return input_val

    def _unmask_output(self, output_val: Any) -> Any:
        """Restore masked placeholders in response."""
        if not self.unmask_response or not self.last_mapping:
            return output_val

        if isinstance(output_val, str):
            return self.masker.unmask(output_val, self.last_mapping)

        if isinstance(output_val, dict) and "content" in output_val and isinstance(output_val["content"], str):
            output_val["content"] = self.masker.unmask(output_val["content"], self.last_mapping)
            return output_val

        if hasattr(output_val, "content") and isinstance(output_val.content, str):
            output_val.content = self.masker.unmask(output_val.content, self.last_mapping)
            return output_val

        return output_val

    def invoke(self, input_val: Any, *args: Any, **kwargs: Any) -> Any:
        """Invoke wrapped model with sanitized input and unmasked output."""
        sanitized_input = self._mask_input(input_val)

        if hasattr(self.llm, "invoke"):
            output = self.llm.invoke(sanitized_input, *args, **kwargs)
        elif callable(self.llm):
            output = self.llm(sanitized_input, *args, **kwargs)
        else:
            raise TypeError(f"Wrapped LLM {type(self.llm)} is neither callable nor implements invoke()")

        return self._unmask_output(output)

    def __call__(self, input_val: Any, *args: Any, **kwargs: Any) -> Any:
        return self.invoke(input_val, *args, **kwargs)
