from ..llm_engine import LLMEngine

class SuperAgent:
    """
    Aggregate and interpret outputs from all agents:
    - Log Analysis Agent
    - Authentication Agent
    - Network Monitoring Agent
    - Vulnerability Analysis Agent
    """
    
    PROMPT_SINGLE_PASS = """Correlate these multi-agent security findings into a concise technical SITREP.
Reference specific IPs, ports, users from the data. If no findings: "SYSTEM STATUS: NOMINAL."

Data:
{data}

Format: THREAT LEVEL | ATTACK CHAIN | IOCs | RECOMMENDED ACTIONS"""
    
    def __init__(self, name: str = "Super_Agent"):
        self.name = name
        self.llm = LLMEngine()

    def analyze(self, data_from_agents: str) -> str:
        # Optimized: Single-pass analysis and reporting to reduce latency
        prompt = self.PROMPT_SINGLE_PASS.format(data=data_from_agents)
        return self.llm.query(prompt, agent_type="super_agent")
