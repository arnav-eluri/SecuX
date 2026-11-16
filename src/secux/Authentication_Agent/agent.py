from ..llm_engine import LLMEngine

class AuthenticationAgent:
    """
    Analyzes authentication-related activity and detects suspicious login behavior.
    """
    
    PROMPT = """Analyze this auth data for brute-force, credential stuffing, unusual IPs, rapid attempts, post-failure logins.
Return JSON: [{{"type","severity","confidence","ip","user","description"}}]. No prose.

Data:
{data}"""
    
    def __init__(self, name: str = "Authentication_Agent"):
        self.name = name
        self.llm = LLMEngine()

    def analyze(self, data: str) -> str:
        prompt = self.PROMPT.format(data=data)
        return self.llm.query(prompt, agent_type="anomaly_detector")
