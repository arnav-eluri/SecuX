import json
import time
import click
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent.parent))

from secux.Log_Analysis_Agent import LogAnalysisAgent
from secux.Authentication_Agent import AuthenticationAgent
from secux.Network_Monitoring_Agent import NetworkMonitoringAgent
from secux.Vulnerability_Analysis_Agent import VulnerabilityAnalysisAgent
from secux.Super_Agent import SuperAgent
from secux.config import get_system_config, get_available_log_files, format_timestamp
from secux.collector import DataCollector


SECUX_BANNER = """
 ███████╗███████╗ ██████╗██╗   ██╗██╗  ██╗
 ██╔════╝██╔════╝██╔════╝██║   ██║╚██╗██╔╝
 ███████╗█████╗  ██║     ██║   ██║ ╚███╔╝ 
 ╚════██║██╔══╝  ██║     ██║   ██║ ██╔██╗ 
 ███████║███████╗╚██████╗╚██████╔╝██╔╝ ██╗
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝
"""

def show_banner():
    from rich.console import Console
    console = Console(force_terminal=True)
    console.print(f"[bold #00B7B5]{SECUX_BANNER}[/bold #00B7B5]")
    console.print("[bold #00B7B5]   Multi-Agent Security Audit & Log Analysis System[/bold #00B7B5]\n")

@click.group(invoke_without_command=True)
@click.version_option(version="0.1.0")
@click.pass_context
def cli(ctx):
    if ctx.invoked_subcommand is None:
        show_banner()
        click.echo(ctx.get_help())
    else:
        pass


@cli.command("logscan")
@click.option(
    "--timeframe",
    "-t",
    type=int,
    default=24,
    help="Timeframe to analyze in hours (default: 24)"
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="LOW",
    help="Minimum severity threshold for findings (default: LOW)"
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Output file path (default: secux_logscan_YYYYMMDD_HHMMSS.json)"
)
@click.option(
    "--append",
    "-a",
    is_flag=True,
    default=False,
    help="Append to existing output file"
)
@click.option(
    "--monitor",
    "-m",
    is_flag=True,
    default=False,
    help="Enable continuous monitoring mode"
)
@click.option(
    "--interval",
    "-i",
    type=int,
    default=60,
    help="Monitoring interval in seconds (default: 60)"
)
@click.option(
    "--paths",
    "-p",
    multiple=True,
    type=click.Path(exists=True),
    help="Specific log file paths to analyze"
)
@click.option(
    "--no-summary",
    is_flag=True,
    default=False,
    help="Suppress summary output"
)
@click.option(
    "--list-logs",
    is_flag=True,
    default=False,
    help="List available log files for this system"
)
def logscan(
    timeframe: int,
    severity: str,
    output: Path,
    append: bool,
    monitor: bool,
    interval: int,
    paths: tuple,
    no_summary: bool,
    list_logs: bool
):
    if list_logs:
        list_available_logs()
        return
    
    if not output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = Path(f"secux_logscan_{timestamp}.json")
    
    if monitor:
        run_monitoring(
            timeframe=timeframe,
            severity=severity,
            output=output,
            append=append,
            interval=interval,
            paths=list(paths) if paths else None
        )
    else:
        run_single_scan(
            timeframe=timeframe,
            severity=severity,
            output=output,
            append=append,
            paths=list(paths) if paths else None,
            show_summary=not no_summary
        )


def list_available_logs():
    config = get_system_config()
    available = get_available_log_files(config)
    
    click.echo(f"\nAvailable log files on {config.hostname} ({config.os}):\n")
    
    for log in available:
        status_icon = "[OK]" if log["status"] == "success" else "[FAIL]"
        
        click.echo(f"  {status_icon} {log['name']}")
        click.echo(f"      Path: {log['path']}")
        if log["status"] == "success":
            click.echo(f"      Size: {log['size']} bytes")
            click.echo(f"      Modified: {format_timestamp(log['modified'])}")
        else:
            click.echo(f"      Status: {log.get('error', 'unknown')}")
        click.echo()


def run_single_scan(
    timeframe: int,
    severity: str,
    output: Path,
    append: bool,
    paths: list,
    show_summary: bool
):
    from rich.console import Console
    console = Console(force_terminal=True)
    try:
        agent = LogAnalysisAgent(
            timeframe_hours=timeframe,
            severity_threshold=severity
        )

        result = agent.run(
            log_paths=paths,
            output_file=output,
            append=append,
            show_summary=show_summary
        )

        if show_summary and output:
            console.print(f"\n[#00B7B5]Results saved to:[/#00B7B5] {output.absolute()}")

    except Exception as e:
        Console(stderr=True).print(f"[red]Error during analysis:[/red] {str(e)}")
        sys.exit(1)


def run_monitoring(
    timeframe: int,
    severity: str,
    output: Path,
    append: bool,
    interval: int,
    paths: list
):
    from rich.console import Console
    from rich.live import Live
    from rich.spinner import Spinner
    
    console = Console()
    
    console.print(f"[#00B7B5]Starting continuous monitoring mode...[/#00B7B5]")
    console.print(f"[#00B7B5]Interval:[/#00B7B5] {interval}s")
    console.print(f"[#00B7B5]Timeframe:[/#00B7B5] {timeframe}h")
    console.print(f"[#00B7B5]Output:[/#00B7B5] {output}")
    console.print("[#005461]Press Ctrl+C to stop[/#005461]\n")
    
    last_scan = datetime.now(timezone.utc)
    agent = LogAnalysisAgent(
        timeframe_hours=timeframe,
        severity_threshold=severity
    )
    
    try:
        while True:
            with console.status(f"[#00B7B5]Scanning logs...[/#00B7B5]") as status:
                result = agent.run_incremental(
                    log_paths=paths,
                    since=last_scan
                )
                
                new_entries, new_findings = result
                
                if new_entries or new_findings:
                    console.print(f"\n[#00B7B5]New events detected:[/#00B7B5] {len(new_entries)}")
                    console.print(f"[#005461]New findings:[/#005461] {len(new_findings)}")
                    
                    for finding in new_findings[:3]:
                        console.print(f"  - [{finding.severity}] {finding.description[:70]}")
                    
                    agent.run(
                        log_paths=paths,
                        output_file=output,
                        append=True,
                        show_summary=False
                    )
                    console.print(f"[dim]Updated: {output}[/dim]")

                last_scan = datetime.now(timezone.utc)

            time.sleep(interval)
            
    except KeyboardInterrupt:
        console.print("\n[#00B7B5]Monitoring stopped.[/#00B7B5]")


@cli.command("audit")
@click.option(
    "--timeframe",
    "-t",
    type=int,
    default=24,
    help="Timeframe to analyze in hours (default: 24)"
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="LOW",
    help="Minimum severity threshold for report (default: LOW)"
)
@click.option(
    "--paths",
    "--path",
    "-p",
    multiple=True,
    type=click.Path(exists=True),
    help="Specific log file paths to analyze"
)
def audit(timeframe: int, severity: str, paths: tuple):
    """Run a full multi-agent security audit and super-agent summary."""
    run_full_audit(timeframe, severity, paths=list(paths) if paths else None)


@cli.command("auth-scan")
@click.argument("data")
def auth_scan(data: str):
    """Run targeted authentication intelligence on specific data."""
    agent = AuthenticationAgent()
    click.echo(agent.analyze(data))


@cli.command("network-scan")
@click.argument("data")
def network_scan(data: str):
    """Run targeted network pattern analysis on specific data."""
    agent = NetworkMonitoringAgent()
    click.echo(agent.analyze(data))


@cli.command("vuln-scan")
@click.argument("data")
def vuln_scan(data: str):
    """Run targeted vulnerability assessment on specific data."""
    agent = VulnerabilityAnalysisAgent()
    click.echo(agent.analyze(data))


def run_full_audit(timeframe: int, severity_threshold: str, paths: list = None):
    from rich.console import Console
    from concurrent.futures import ThreadPoolExecutor

    console = Console(highlight=False, force_terminal=True)
    console.print("\n[bold #00B7B5]>>> Initializing Fast Parallel Multi-Agent Security Audit[/bold #00B7B5]")
    console.print(f"[dim]Timeframe: {timeframe}h | Threshold: {severity_threshold}[/dim]\n")

    # PHASE 1 & 1.5: Parallel Data Collection & Base Log Analysis
    console.print("[bold #00B7B5]Phase 1: Concurrent Data Collection & Log Analysis...[/bold #00B7B5]")
    collector = DataCollector()
    log_agent = LogAnalysisAgent(timeframe_hours=timeframe, severity_threshold=severity_threshold)

    with ThreadPoolExecutor(max_workers=3) as executor:
        # Start log analysis and system intelligence collection in parallel
        future_log_results = executor.submit(log_agent.run, log_paths=paths, show_summary=False, skip_ai_summary=True)
        future_net_data = executor.submit(collector.get_network_context)
        future_vuln_data = executor.submit(collector.get_vulnerability_context)

        with console.status("[bold #00B7B5]Collecting multi-source intelligence...[/bold #00B7B5]"):
            log_results = future_log_results.result()
            console.print("  [#005461]|--[/#005461] Base Log Analysis: [#00B7B5]OK[/#00B7B5]")
            
            net_context = future_net_data.result()
            console.print("  [#005461]|--[/#005461] Network Context: [#00B7B5]OK[/#00B7B5]")
            
            vuln_context = future_vuln_data.result()
            console.print("  [#005461]|--[/#005461] Vulnerability Context: [#00B7B5]OK[/#00B7B5]")

    # PHASE 1.6: Dependent Data Collection (must follow Log Analysis)
    with console.status("[bold #00B7B5]Phase 1.5: Finalizing Auth Context...[/bold #00B7B5]"):
        auth_context = collector.get_auth_context(log_results.get("findings", []))
        console.print("[#00B7B5]OK[/#00B7B5] Auth Intelligence Context Prepared")

    # PHASE 2: Parallel AI Analysis (Concurrent)
    console.print("[bold #00B7B5]Phase 2: Launching Parallel AI Analysts (Log, Auth, Net, Vuln)...[/bold #00B7B5]")

    def run_agent(agent_class, context):
        agent = agent_class()
        return agent.analyze(context)

    with ThreadPoolExecutor(max_workers=4) as executor:
        # Submit all AI tasks, including the Log AI Summary which we deferred
        future_auth = executor.submit(run_agent, AuthenticationAgent, auth_context)
        future_net = executor.submit(run_agent, NetworkMonitoringAgent, net_context)
        future_vuln = executor.submit(run_agent, VulnerabilityAnalysisAgent, vuln_context)
        future_log_sum = executor.submit(log_agent.generate_ai_summary, log_results.get("findings", []))

        with console.status("[bold #00B7B5]Waiting for parallel AI results...[/bold #00B7B5]"):
            auth_results = future_auth.result()
            console.print("  [#005461]|--[/#005461] Authentication Intelligence: [#00B7B5]OK[/#00B7B5]")

            net_results = future_net.result()
            console.print("  [#005461]|--[/#005461] Network Patterns: [#00B7B5]OK[/#00B7B5]")

            vuln_results = future_vuln.result()
            console.print("  [#005461]|--[/#005461] Vulnerability Assessment: [#00B7B5]OK[/#00B7B5]")
            
            log_ai_summary = future_log_sum.result()
            console.print("  [#005461]\\--[/#005461] Log AI Summary: [#00B7B5]OK[/#00B7B5]")

    # PHASE 3: Super Agent Correlation (Sequential)
    super_agent = SuperAgent()
    
    with console.status("[bold #00B7B5]Phase 3: Super Agent Correlation & Interpretation...[/bold #00B7B5]") as status:
        raw_findings = log_results.get("findings", [])
        severity_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        top_finding_summaries = []
        
        for f in raw_findings:
            sev = f.get("severity", "LOW")
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            if len(top_finding_summaries) < 8:
                ev = f.get("evidence", {})
                top_finding_summaries.append(
                    f"[{sev}] {f.get('type','?')} - {f.get('description','')[:120]} "
                    f"(IP={ev.get('source_ip','N/A')}, user={ev.get('target_user','N/A')})"
                )

        summary_context = {
            "log_analysis": {
                "total_findings": len(raw_findings),
                "severity_breakdown": severity_breakdown,
                "top_findings": top_finding_summaries,
                "ai_summary_excerpt": (log_ai_summary or "")[:1000], # Increased context
            },
            "auth_intelligence": (auth_results or "No significant auth findings")[:3000],
            "network_patterns": (net_results or "No network data available (non-Windows or collection failed)")[:3000],
            "vulnerabilities": (vuln_results or "No critical vulnerabilities identified")[:3000],
        }

        final_report = super_agent.analyze(str(summary_context))
        console.print("[#00B7B5]OK[/#00B7B5] Full Audit Process Complete\n")

    console.print(final_report)

@cli.command("help")
def help_cmd():
    show_banner()
    click.echo("""
SecuX Log Analysis Agent
========================

Usage:
  secux logscan [OPTIONS]

Commands:
  logscan      Analyze system logs for security anomalies
  audit        Run a full multi-agent audit with AI orchestration
  auth-scan    Run standalone authentication intelligence
  network-scan Run standalone network pattern analysis
  vuln-scan    Run standalone vulnerability assessment
  help         Show this help message

Logscan Options:
  -t, --timeframe HOURS      Timeframe to analyze (default: 24)
  -s, --severity LEVEL       Minimum severity: LOW, MEDIUM, HIGH, CRITICAL
  -o, --output PATH          Output file path
  -a, --append               Append to existing output file
  -m, --monitor              Enable continuous monitoring
  -i, --interval SECONDS     Monitoring interval (default: 60)
  -p, --paths PATH           Specific log file paths
  --no-summary               Suppress summary output
  --list-logs                List available log files

Audit Options:
  -t, --timeframe HOURS      Timeframe to analyze (default: 24)
  -s, --severity LEVEL       Minimum severity threshold
  -p, --path, --paths PATH   Specific log file paths

Examples:
  secux logscan                          Analyze last 24 hours
  secux logscan --timeframe 48           Analyze last 48 hours
  secux logscan --severity HIGH          Show only HIGH+ findings
  secux logscan --output report.json     Save to file
  secux logscan --monitor                Continuous monitoring
  secux logscan --list-logs              Show available logs
  secux audit --path test.log            Run full audit on specific file
""")


def main():
    cli()


if __name__ == "__main__":
    main()
