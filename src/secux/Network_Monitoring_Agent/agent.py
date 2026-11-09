from ..llm_engine import LLMEngine

class NetworkMonitoringAgent:
    """
    Analyzes network activity and detects suspicious traffic patterns.
    """
    
    PROMPT = """
    You are the Network Monitoring Agent in a multi-agent cybersecurity system.

    Task:
    Analyze network activity and detect suspicious traffic patterns.

    Instructions:
    - Monitor incoming/outgoing traffic and connection logs
    - Detect:
      • unusual traffic spikes
      • repeated requests from same IP
      • unknown or blacklisted IP connections
      • port scanning behavior
      • abnormal request frequency
    - Identify potential reconnaissance or attack patterns

    Assign:
    - severity: LOW | MEDIUM | HIGH | CRITICAL
    - confidence: 0.0–1.0

    Data to analyze:
    {data}

    Output:
    Return only structured JSON with findings and evidence.
    No explanations outside JSON.
    """
    
    def __init__(self, name: str = "Network_Monitoring_Agent"):
        self.name = name
        self.llm = LLMEngine()

    def analyze(self, data: str) -> str:
        prompt = self.PROMPT.format(data=data)
        return self.llm.query(prompt, agent_type="anomaly_detector")
