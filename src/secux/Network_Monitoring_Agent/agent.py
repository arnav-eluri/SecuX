from ..llm_engine import LLMEngine

class NetworkMonitoringAgent:
    """
    Analyzes network activity and detects suspicious traffic patterns.
    """
    
    PROMPT = """Analyze this network data for traffic spikes, repeated IPs, port scanning, blacklisted connections, abnormal frequency.
Return JSON: [{{"type","severity","confidence","ip","port","description"}}]. No prose.

Data:
{data}"""
    
    def __init__(self, name: str = "Network_Monitoring_Agent"):
        self.name = name
        self.llm = LLMEngine()

    def analyze(self, data: str) -> str:
        prompt = self.PROMPT.format(data=data)
        return self.llm.query(prompt, agent_type="anomaly_detector")
