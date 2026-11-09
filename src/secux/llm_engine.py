import os
import time
import requests
import json
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

class LLMEngine:
    def __init__(self):
        # Configuration from environment
        self.provider = os.getenv("LLM_PROVIDER", "local").lower() # 'local', 'google', or 'openrouter'
        self.local_model = os.getenv("LOCAL_MODEL", "llama3.2:3b")
        self.local_url = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/api/generate")
        
        # OpenRouter setup
        self.openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
        self.openrouter_model = os.getenv("OPENROUTER_MODEL", "qwen/qwen3-coder:free")
        
        # Per-agent model configuration (uses :free variants on OpenRouter)
        # Verified against live https://openrouter.ai/api/v1/models — update periodically
        self.model_config = {
            "super_agent":       "qwen/qwen3-coder:free", # State-of-the-art coding and logic
            "log_analysis":      "qwen/qwen3-coder:free", 
            "anomaly_detector":  "qwen/qwen3-coder:free",
            "vuln_analysis":     "qwen/qwen3-coder:free", 
            "report_generator":  "qwen/qwen3-coder:free"  # High-quality technical output
        }
        
        # Google setup (optional fallback)
        self.google_api_key = os.getenv("GEMINI_API_KEY")
        if self.google_api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.google_api_key)
                self.google_model = genai.GenerativeModel("gemini-1.5-flash")
            except ImportError:
                self.google_model = None
        else:
            self.google_model = None

    def query(self, prompt: str, agent_type: Optional[str] = None) -> str:
        res = None
        if self.provider == "local":
            res = self._query_local(prompt)
        elif self.provider == "google":
            res = self._query_google(prompt)
        elif self.provider == "openrouter":
            res = self._query_openrouter(prompt, agent_type)
        else:
            res = f"Error: Unknown LLM provider '{self.provider}'"
        
        return res if res is not None else "Error: LLM provider returned None or empty response."

    def _query_local(self, prompt: str) -> Optional[str]:
        """Query local LLM via Ollama API."""
        try:
            payload = {
                "model": self.local_model,
                "prompt": prompt,
                "stream": False
            }
            response = requests.post(self.local_url, json=payload, timeout=300)
            response.raise_for_status()
            return response.json().get("response")
        except Exception as e:
            return f"Error querying local LLM (Ollama): {str(e)}"

    def _query_google(self, prompt: str) -> Optional[str]:
        """Query Google Gemini API."""
        if not self.google_model:
            return "Error: Gemini model not initialized. Check GEMINI_API_KEY or install google-generativeai."
        
        try:
            response = self.google_model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error querying Gemini: {str(e)}"

    def _query_openrouter(self, prompt: str, agent_type: Optional[str] = None) -> Optional[str]:
        """Query OpenRouter API with exponential backoff retry on rate limits."""
        if not self.openrouter_api_key:
            return "Error: OPENROUTER_API_KEY not found in environment."

        # Determine model based on agent_type
        model = self.openrouter_model
        if agent_type and agent_type in self.model_config:
            model = self.model_config[agent_type]

        max_retries = 3
        backoff = 5  # seconds

        for attempt in range(1, max_retries + 1):
            try:
                response = requests.post(
                    url="https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.openrouter_api_key}",
                        "HTTP-Referer": "https://github.com/itseluriiiiii/SecuX",
                        "X-Title": "SecuX Security Agent",
                        "Content-Type": "application/json"
                    },
                    data=json.dumps({
                        "model": model,
                        "messages": [
                            {"role": "user", "content": prompt}
                        ]
                    }),
                    timeout=300
                )

                # Handle rate limiting gracefully
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", backoff))
                    if attempt < max_retries:
                        time.sleep(retry_after)
                        backoff *= 2
                        continue
                    return f"[Rate limited] OpenRouter ({model}) — too many requests. Try again in {retry_after}s."

                response.raise_for_status()
                result = response.json()
                try:
                    content = result["choices"][0]["message"].get("content")
                    return content if content is not None else "Error: OpenRouter returned empty content."
                except (KeyError, IndexError):
                    return f"Error: Unexpected response format from OpenRouter: {json.dumps(result)}"

            except requests.exceptions.HTTPError as e:
                if attempt < max_retries and e.response is not None and e.response.status_code in (429, 503):
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                return f"Error querying OpenRouter ({model}): {str(e)}"
            except Exception as e:
                return f"Error querying OpenRouter ({model}): {str(e)}"


