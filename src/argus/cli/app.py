"""Main CLI application using Typer."""

import asyncio
import json
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from argus.version import __version__
from argus.core.config import get_settings
from argus.core.logging import setup_logging

app = typer.Typer(
    name="argus",
    help="Argus - AI-powered security reconnaissance tool",
    no_args_is_help=True,
)

console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"Argus version {__version__}")
        raise typer.Exit()


@app.callback()
def main_callback(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """Argus - The all-seeing eye for your security."""
    setup_logging()


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="Target domain or IP address")],
    modules: Annotated[
        Optional[str],
        typer.Option(
            "--modules",
            "-m",
            help="Modules: dns,whois,rdap,ports,webtech,crtsh,vuln,ssl,email,security,js,headers,discovery,favicon,asn,graphql",
        ),
    ] = None,
    full: Annotated[
        bool,
        typer.Option("--full", "-f", help="Run all modules"),
    ] = False,
    analyze: Annotated[
        bool,
        typer.Option("--analyze", "-a", help="Enable AI analysis"),
    ] = False,
    ai_provider: Annotated[
        str,
        typer.Option(
            "--ai-provider",
            "-p",
            help="AI provider: anthropic, openai, ollama",
        ),
    ] = "anthropic",
    output: Annotated[
        Optional[Path],
        typer.Option("--output", "-o", help="Output file path (JSON or HTML)"),
    ] = None,
    format_type: Annotated[
        str,
        typer.Option("--format", help="Output format: json, table, html"),
    ] = "table",
    html_report: Annotated[
        Optional[Path],
        typer.Option("--html", help="Generate HTML report to specified path"),
    ] = None,
    extended_subdomains: Annotated[
        bool,
        typer.Option("--extended-subdomains", help="Extended subdomain enum (20+ sources)"),
    ] = False,
    takeover_check: Annotated[
        bool,
        typer.Option("--takeover", help="Check for subdomain takeover vulnerabilities"),
    ] = False,
    kev_check: Annotated[
        bool,
        typer.Option("--kev", help="Check vulnerabilities against CISA KEV catalog"),
    ] = True,
    wayback: Annotated[
        bool,
        typer.Option("--wayback", help="Extract URLs from Wayback Machine (slow)"),
    ] = False,
    language: Annotated[
        str,
        typer.Option(
            "--language",
            "-l",
            help="Output language for AI analysis (ISO code: en, ja, etc.)",
        ),
    ] = "en",
) -> None:
    """
    Scan a target for security reconnaissance.

    Examples:
        argus scan example.com
        argus scan example.com --full --analyze
        argus scan example.com --modules dns,ports
        argus scan example.com --analyze --ai-provider ollama
    """
    from argus.orchestration.coordinator import ScanCoordinator
    from argus.models import ScanTarget, ScanOptions

    console.print(
        Panel(
            f"[bold blue]Argus Scan[/bold blue]\n"
            f"Target: [green]{target}[/green]",
            title="Starting Scan",
        )
    )

    # Build scan options
    enabled_modules = []
    if full:
        enabled_modules = [
            "dns", "whois", "rdap", "ports", "webtech", "crtsh", "vuln",
            "ssl", "email", "security", "js", "headers", "discovery",
            "favicon", "asn", "graphql"
        ]
    elif modules:
        enabled_modules = [m.strip().lower() for m in modules.split(",")]
    else:
        enabled_modules = ["dns", "whois", "ports", "crtsh"]  # Default modules

    try:
        scan_target = ScanTarget(domain=target if "." in target else None,
                                  ip_address=target if "." not in target or target.replace(".", "").isdigit() else None)
    except Exception as e:
        console.print(f"[red]Invalid target: {e}[/red]")
        raise typer.Exit(1) from None

    options = ScanOptions(
        dns_enabled="dns" in enabled_modules,
        whois_enabled="whois" in enabled_modules,
        rdap_enabled="rdap" in enabled_modules,
        port_scan_enabled="ports" in enabled_modules,
        webtech_enabled="webtech" in enabled_modules,
        crtsh_enabled="crtsh" in enabled_modules,
        vuln_scan_enabled="vuln" in enabled_modules,
        ssl_scan_enabled="ssl" in enabled_modules,
        email_scan_enabled="email" in enabled_modules,
        security_scan_enabled="security" in enabled_modules,
        js_analysis_enabled="js" in enabled_modules,
        headers_scan_enabled="headers" in enabled_modules,
        discovery_scan_enabled="discovery" in enabled_modules,
        favicon_scan_enabled="favicon" in enabled_modules,
        asn_scan_enabled="asn" in enabled_modules,
        graphql_scan_enabled="graphql" in enabled_modules,
        takeover_scan_enabled=takeover_check,
        subdomain_enum_extended=extended_subdomains,
        kev_check_enabled=kev_check,
        wayback_scan_enabled=wayback,
        ai_analysis_enabled=analyze,
        ai_provider=ai_provider,  # type: ignore
        output_language=language,
    )

    # Run scan
    coordinator = ScanCoordinator()

    with console.status("[bold green]Scanning...[/bold green]") as status:
        try:
            result = asyncio.run(coordinator.run_scan(scan_target, options))
        except Exception as e:
            console.print(f"[red]Scan failed: {e}[/red]")
            raise typer.Exit(1) from None

    # Output results
    if output:
        if str(output).endswith(".html"):
            from argus.reports import HTMLReportGenerator
            generator = HTMLReportGenerator()
            generator.generate(result, output)
            console.print(f"[green]HTML report saved to {output}[/green]")
        else:
            with open(output, "w") as f:
                json.dump(result.to_json_dict(), f, indent=2, default=str)
            console.print(f"[green]Results saved to {output}[/green]")

    # Generate HTML report if requested
    if html_report:
        from argus.reports import HTMLReportGenerator
        generator = HTMLReportGenerator()
        generator.generate(result, html_report)
        console.print(f"[green]HTML report saved to {html_report}[/green]")

    if not output and not html_report:
        _display_results(result, format_type)


def _display_results(result, format_type: str) -> None:
    """Display scan results."""
    from argus.cli.formatters.table import format_scan_result

    if format_type == "json":
        console.print_json(result.model_dump_json())
    else:
        format_scan_result(console, result)


@app.command()
def config(
    show: Annotated[
        bool,
        typer.Option("--show", "-s", help="Show current configuration"),
    ] = False,
    validate: Annotated[
        bool,
        typer.Option("--validate", help="Validate configuration"),
    ] = False,
) -> None:
    """Manage configuration settings."""
    settings = get_settings()

    if show or not validate:
        table = Table(title="Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("API Host", settings.api_host)
        table.add_row("API Port", str(settings.api_port))
        table.add_row("Log Level", settings.log_level)
        table.add_row("Log Format", settings.log_format)
        table.add_row("Default AI Provider", settings.default_ai_provider)
        table.add_row("Ollama Host", settings.ollama_host)
        table.add_row("Ollama Model", settings.ollama_model)
        table.add_row("Output Language", settings.output_language)
        table.add_row(
            "Anthropic API Key",
            "[green]Set[/green]" if settings.anthropic_api_key else "[red]Not set[/red]",
        )
        table.add_row(
            "OpenAI API Key",
            "[green]Set[/green]" if settings.openai_api_key else "[red]Not set[/red]",
        )
        table.add_row("Max Concurrent Scans", str(settings.max_concurrent_scans))
        table.add_row("DNS Timeout", f"{settings.dns_timeout}s")
        table.add_row("Port Scan Timeout", f"{settings.port_scan_timeout}s")
        table.add_row("HTTP Timeout", f"{settings.http_timeout}s")

        console.print(table)

    if validate:
        errors = []

        if settings.default_ai_provider == "anthropic" and not settings.anthropic_api_key:
            errors.append("ANTHROPIC_API_KEY is required for Anthropic provider")
        if settings.default_ai_provider == "openai" and not settings.openai_api_key:
            errors.append("OPENAI_API_KEY is required for OpenAI provider")

        if errors:
            console.print("[red]Configuration errors:[/red]")
            for error in errors:
                console.print(f"  - {error}")
            raise typer.Exit(1)
        else:
            console.print("[green]Configuration is valid[/green]")


@app.command()
def serve(
    host: Annotated[
        str,
        typer.Option("--host", "-h", help="Host to bind to"),
    ] = "0.0.0.0",
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="Port to bind to"),
    ] = 8000,
    reload: Annotated[
        bool,
        typer.Option("--reload", "-r", help="Enable auto-reload for development"),
    ] = False,
) -> None:
    """Start the REST API server."""
    import uvicorn

    console.print(
        Panel(
            f"[bold blue]Starting API Server[/bold blue]\n"
            f"Host: [green]{host}[/green]\n"
            f"Port: [green]{port}[/green]\n"
            f"Docs: [cyan]http://{host}:{port}/docs[/cyan]",
            title="API Server",
        )
    )

    uvicorn.run(
        "argus.api.app:app",
        host=host,
        port=port,
        reload=reload,
    )


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
