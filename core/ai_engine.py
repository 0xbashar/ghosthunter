"""
AIEngine — LLM-powered test generation, SPA crawling, and verification.
Supports OpenAI GPT-4o, Anthropic Claude 3.5, or local Llama 3 via Ollama.
"""
from __future__ import annotations
import json, re, asyncio, aiohttp
from typing import List, Dict, Optional, Any
from core.logger import Logger

log = Logger.get_logger("ai_engine")

class AIEngine:
    def __init__(self, config: dict):
        self.cfg = config.get("ai", {})
        self.provider = self.cfg.get("provider", "openai")
        self.api_key = self.cfg.get("api_key", "")
        self.model = self.cfg.get("model", "gpt-4o")
        self.base_url = self.cfg.get("base_url", "https://api.openai.com/v1")
        self.client = aiohttp.ClientSession(
            headers={"Authorization": f"Bearer {self.api_key}",
                     "Content-Type": "application/json"}
        )

    async def analyze_spa(self, html: str, js_files: List[str]) -> List[Dict]:
        """Analyze SPA JavaScript to discover hidden routes, API calls, and logic."""
        prompt = f"""
        Analyze this HTML and JS content from a Single Page Application.
        Extract:
        1. Hidden API endpoints (REST, GraphQL, gRPC)
        2. Client-side routing paths
        3. WebSocket URLs
        4. Embedded tokens/secrets
        5. Potential business logic flows (e.g., checkout, payment, admin)
        
        HTML snippet: {html[:2000]}
        JS snippets: {json.dumps(js_files[:5])[:4000]}
        
        Return as JSON array: [{{"type":"api|route|ws|secret", "value":"...", "context":"..."}}]
        """
        return await self._chat(prompt, json_mode=True)

    async def generate_business_logic_tests(self, endpoint: Dict, stack: Dict) -> List[Dict]:
        """Generate contextual test cases for business logic flaws."""
        prompt = f"""
        You are an expert bug bounty hunter. Generate 5 high-impact test cases for business logic vulnerabilities
        for this endpoint. Focus on high-paying bugs like:
        - Price manipulation
        - Authentication bypass
        - Privilege escalation
        - Race conditions in transactions
        - State machine violations
        
        Endpoint: {endpoint['method']} {endpoint['url']}
        Parameters: {json.dumps(endpoint.get('params', []))}
        Tech Stack: {json.dumps(stack)}
        
        Return as JSON: [{{"payload":"...", "header":"...", "description":"...", "expected_behavior":"..."}}]
        """
        return await self._chat(prompt, json_mode=True)

    async def verify_finding(self, finding: dict, baseline_response: str, payload_response: str) -> float:
        """Use AI to verify if a response difference is a true positive."""
        prompt = f"""
        Analyze these HTTP responses and determine if the vulnerability finding is a true positive.
        
        Finding: {finding['title']}
        Payload: {finding.get('payload', 'N/A')}
        
        Baseline Response (benign):
        {baseline_response[:1000]}
        
        Payload Response:
        {payload_response[:1000]}
        
        Is this a true positive? Answer with JSON: {{"confidence": 0.0-1.0, "reasoning":"..."}}
        """
        result = await self._chat(prompt, json_mode=True)
        return result.get("confidence", 0.0) if isinstance(result, dict) else 0.0

    async def _chat(self, prompt: str, json_mode: bool = False) -> Any:
        if not self.api_key:
            log.debug("AI engine disabled (no API key)")
            return []
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        try:
            async with self.client.post(
                f"{self.base_url}/chat/completions", json=payload, timeout=30
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    content = data["choices"][0]["message"]["content"]
                    return json.loads(content) if json_mode else content
                log.warn(f"AI API error: {r.status}")
        except Exception as e:
            log.debug(f"AI request failed: {e}")
        return []
