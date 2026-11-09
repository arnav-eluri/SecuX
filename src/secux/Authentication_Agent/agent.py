from ..llm_engine import LLMEngine

class AuthenticationAgent:
    """
    Analyzes authentication-related activity and detects suspicious login behavior.
    """
    
    PROMPT = """
    You are the Authentication Agent in a multi-agent cybersecurity system.

    Task:
    Analyze authentication-related activity and detect suspicious login behavior.

    Instructions:
    - Monitor login attempts, sessions, and credential usage
    - Detect:
      • brute-force attacks (multiple failed logins)
      • credential stuffing patterns
      • unusual login locations/IPs
      • rapid login attempts across accounts
      • successful login after repeated failures
    - Identify user-specific anomalies

    Assign:
    - severity: LOW | MEDIUM | HIGH | CRITICAL
    - confidence: 0.0–1.0

    Data to analyze:
    {data}

    Output:
    Return only structured JSON with findings and evidence.
    No extra explanation.
    """
    
    def __init__(self, name: str = "Authentication_Agent"):
        self.name = name
        self.llm = LLMEngine()

    def analyze(self, data: str) -> str:
        prompt = self.PROMPT.format(data=data)
        return self.llm.query(prompt, agent_type="anomaly_detector")
