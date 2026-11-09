from ..llm_engine import LLMEngine

class SuperAgent:
    """
    Aggregate and interpret outputs from all agents:
    - Log Analysis Agent
    - Authentication Agent
    - Network Monitoring Agent
    - Vulnerability Analysis Agent
    """
    
    PROMPT_SINGLE_PASS = """
    You are the SecuX Super Agent and Senior Security Analyst.
    
    Task: Correlate all agent findings, identify high-level threat patterns, and convert them into a high-density, raw technical SITREP (Situation Report).
    
    Data from Analysts:
    {data}
    
    CRITICAL INSTRUCTIONS:
    - DO NOT use generic "premade" sounding templates.
    - If the data indicates no findings, state: "SYSTEM STATUS: NOMINAL. No immediate threat vectors detected."
    - Be RAW and TECHNICAL. Mention specific IPs, ports, processes, or log file names found in the data.
    - Use a technical, concise analyst tone.
    - Format: Use a clean, terminal-styled layout with high-density information.
    """
    
    def __init__(self, name: str = "Super_Agent"):
        self.name = name
        self.llm = LLMEngine()

    def analyze(self, data_from_agents: str) -> str:
        # Optimized: Single-pass analysis and reporting to reduce latency
        prompt = self.PROMPT_SINGLE_PASS.format(data=data_from_agents)
        return self.llm.query(prompt, agent_type="super_agent")
