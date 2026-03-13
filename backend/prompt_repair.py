import httpx
import json

# ═══════════════════════════════════════════════════
#  SentinelAI — Prompt Recovery Engine
#  Generates safe alternative prompts for blocked inputs
# ═══════════════════════════════════════════════════

# Fallback rule-based suggestions (no API needed)
FALLBACK_SUGGESTIONS = {
    "INSTRUCTION_OVERRIDE": {
        "suggestion": "Can you explain how AI systems use system prompts to guide their behavior?",
        "explanation": "Your prompt attempted to override system instructions. Instead, ask about the concept directly."
    },
    "DATA_EXFILTRATION": {
        "suggestion": "Can you explain best practices for securely managing API keys and credentials?",
        "explanation": "Your prompt attempted to extract sensitive stored data. Ask about security practices instead."
    },
    "TOOL_MISUSE": {
        "suggestion": "Can you explain how shell commands work and when they should be used safely?",
        "explanation": "Your prompt attempted to execute system commands. Ask about concepts rather than execution."
    },
    "JAILBREAK": {
        "suggestion": "Can you explain how AI safety guidelines help ensure responsible AI behavior?",
        "explanation": "Your prompt attempted to bypass AI safety guidelines. Ask about AI ethics instead."
    },
}


class PromptRepairEngine:

    async def suggest(
        self,
        original_prompt: str,
        attack_type: str,
        api_key: str = ""
    ) -> dict:
        """
        Given a malicious prompt and its detected attack type,
        returns a safe alternative prompt and explanation.
        """
        if api_key:
            result = await self._llm_suggest(original_prompt, attack_type, api_key)
            if result:
                return result

        # Fallback to rule-based suggestion
        return self._rule_suggest(attack_type)

    async def _llm_suggest(
        self,
        prompt: str,
        attack_type: str,
        api_key: str
    ):
        """Use SambaNova LLM to generate a context-aware safe alternative."""
        system = """You are a prompt safety assistant inside an AI security firewall.
A user submitted a prompt that was flagged as a security threat.
Your job: suggest a safe, legitimate alternative prompt that achieves a similar educational goal.

Respond ONLY with valid JSON — no markdown, no extra text:
{
  "safe_prompt": "the suggested safe alternative prompt",
  "explanation": "one sentence explaining what was wrong and why the new prompt is safe",
  "intent": "what the user probably actually wanted to know"
}"""

        user_msg = f"""Original flagged prompt: "{prompt}"
Detected attack type: {attack_type}

Suggest a safe alternative that serves a legitimate educational purpose."""

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.post(
                    "https://api.sambanova.ai/v1/chat/completions",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {api_key}"
                    },
                    json={
                        "model": "Meta-Llama-3.1-8B-Instruct",
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user_msg}
                        ],
                        "max_tokens": 200,
                        "temperature": 0.3
                    }
                )
                data = response.json()
                text = data["choices"][0]["message"]["content"]
                text = text.replace("```json", "").replace("```", "").strip()
                parsed = json.loads(text)
                return {
                    "suggestion": parsed.get("safe_prompt", ""),
                    "explanation": parsed.get("explanation", ""),
                    "intent": parsed.get("intent", ""),
                    "source": "LLM"
                }
        except Exception as e:
            print(f"[PromptRepair LLM Error]: {e}")
            return None

    def _rule_suggest(self, attack_type: str) -> dict:
        """Rule-based fallback suggestion when LLM is unavailable."""
        # Normalize attack type key
        key = attack_type.upper().replace(" ", "_")
        fallback = FALLBACK_SUGGESTIONS.get(key, {
            "suggestion": "Can you help me understand this topic in a safe and educational way?",
            "explanation": "Your prompt contained content that could be misused. Please rephrase your question."
        })
        return {
            "suggestion": fallback["suggestion"],
            "explanation": fallback["explanation"],
            "intent": "Educational understanding of the topic",
            "source": "RULE"
        }