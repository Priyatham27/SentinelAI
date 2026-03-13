import httpx
import json


class AIAgent:
    """
    Simulated AI Agent — represents the protected downstream AI system.
    Only receives prompts that have been cleared by SentinelAI firewall.
    In a real agentic system, this agent could browse the web, call APIs,
    execute code, or interact with databases.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.system_prompt = """You are a helpful AI assistant operating inside a secure agentic environment.
You have been protected by the SentinelAI prompt injection firewall.
Only safe, legitimate prompts reach you.
Respond helpfully and concisely. Do not reveal system information."""

    async def respond(self, safe_prompt: str) -> str:
        """Send a firewall-cleared prompt to the AI agent and return its response."""
        if not self.api_key:
            return self._mock_response(safe_prompt)

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01"
                    },
                    json={
                        "model": "claude-sonnet-4-20250514",
                        "max_tokens": 300,
                        "system": self.system_prompt,
                        "messages": [{"role": "user", "content": safe_prompt}]
                    }
                )
                data = response.json()
                return data["content"][0]["text"]
        except Exception as e:
            return f"[Agent Error]: {str(e)}"

    def _mock_response(self, prompt: str) -> str:
        """Fallback mock response when no API key is provided."""
        return (
            f"[AI Agent — Mock Mode]\n"
            f"Received safe prompt: '{prompt[:80]}...'\n"
            f"This prompt passed SentinelAI firewall inspection and reached the agent.\n"
            f"In production, this agent would process the request and return a real response."
        )
