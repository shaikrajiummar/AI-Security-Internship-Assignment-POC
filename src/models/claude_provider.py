"""
Anthropic Claude Model Provider implementation.
Supports anthropic package or direct httpx REST calls.
"""
import os
import json
from typing import Dict, Any, List, Optional
from src.models.base import BaseModelProvider
from src.models.mock_provider import MockProvider

class ClaudeProvider(BaseModelProvider):
    def __init__(self, model_name: str = "claude-3-5-sonnet-20241022", api_key: Optional[str] = None):
        super().__init__(model_name=model_name, api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
        self._fallback_mock = MockProvider(model_name=f"mock-{model_name}", flavor="claude")

    def _call_anthropic_api(self, prompt: str, system_prompt: str = "", temperature: float = 0.0) -> Optional[str]:
        if not self.api_key:
            return None
        try:
            import httpx
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            body = {
                "model": self.model_name,
                "max_tokens": 1024,
                "temperature": temperature,
                "messages": [{"role": "user", "content": prompt}]
            }
            if system_prompt:
                body["system"] = system_prompt

            with httpx.Client(timeout=30.0) as client:
                res = client.post("https://api.anthropic.com/v1/messages", headers=headers, json=body)
                if res.status_code == 200:
                    data = res.json()
                    content = data.get("content", [])
                    text_parts = [c.get("text", "") for c in content if c.get("type") == "text"]
                    return "".join(text_parts)
                else:
                    print(f"[ClaudeProvider] API error ({res.status_code}): {res.text}")
                    return None
        except Exception as e:
            print(f"[ClaudeProvider] HTTP call failed ({e}). Falling back to mock simulation.")
            return None

    def generate(self, prompt: str, system_prompt: str = "", temperature: float = 0.0) -> str:
        api_res = self._call_anthropic_api(prompt, system_prompt, temperature)
        if api_res is not None:
            return api_res
        return self._fallback_mock.generate(prompt, system_prompt, temperature)

    def generate_tool_call(
        self,
        prompt: str,
        system_prompt: str = "",
        available_tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.0
    ) -> Dict[str, Any]:
        if self.api_key:
            tools_desc = json.dumps(available_tools or [], indent=2)
            sys_msg = (
                f"{system_prompt}\n"
                f"You have access to these tools:\n{tools_desc}\n"
                "You must respond ONLY with a valid JSON object formatted as: "
                '{"thought": "...", "tool_name": "name_or_null", "tool_args": {...}}'
            )
            api_res = self._call_anthropic_api(prompt, sys_msg, temperature)
            if api_res and "{" in api_res and "}" in api_res:
                try:
                    json_str = api_res[api_res.find("{"):api_res.rfind("}") + 1]
                    data = json.loads(json_str)
                    return {
                        "tool_name": data.get("tool_name"),
                        "tool_args": data.get("tool_args", {}),
                        "thought": data.get("thought", ""),
                        "raw_response": api_res
                    }
                except Exception:
                    pass

        return self._fallback_mock.generate_tool_call(prompt, system_prompt, available_tools, temperature)
