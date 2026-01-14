"""
aisentry - Command line interface for AI security scanning and testing.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import click
from importlib.metadata import version as get_version
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from aisentry.config import load_config
from aisentry.core.scanner import StaticScanner, is_remote_url
from aisentry.core.tester import DETECTOR_REGISTRY, LiveTester
from aisentry.providers import PROVIDER_MAP
from aisentry.reporters.html_reporter import HTMLReporter
from aisentry.reporters.json_reporter import JSONReporter
from aisentry.reporters.sarif_reporter import SARIFReporter

console = Console()


def setup_logging(verbose: bool):
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def _get_version():
    """Get version from package metadata."""
    try:
        return get_version("aisentry")
    except Exception:
        return "unknown"


@click.group()
@click.version_option(version=_get_version(), prog_name="aisentry")
def main():
    """
    aisentry - Security scanning and testing for AI/LLM applications.

    Commands:

    \b
      scan   Static code analysis for OWASP LLM Top 10 vulnerabilities
      test   Live model testing for LLM security vulnerabilities
      audit  Security posture audit with maturity scoring
    """
    pass


@main.command()
@click.argument("path", type=str)
@click.option(
    "-o", "--output",
    type=click.Choice(["text", "json", "html", "sarif"]),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "-f", "--output-file",
    type=click.Path(),
    help="Write output to file",
)
@click.option(
    "-s", "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default="info",
    help="Minimum severity to report (default: info)",
)
@click.option(
    "-c", "--confidence",
    type=float,
    default=None,
    help="Global confidence threshold (0.0-1.0, default: 0.7)",
)
@click.option(
    "--category",
    multiple=True,
    help="Filter by OWASP category (LLM01-LLM10)",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--audit/--no-audit",
    default=True,
    help="Include security posture audit in HTML reports (default: enabled)",
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Path to .aisentry.yaml config file",
)
@click.option(
    "--dedup",
    type=click.Choice(["exact", "off"]),
    default=None,
    help="Deduplication mode (default: exact)",
)
@click.option(
    "--exclude-dir",
    multiple=True,
    help="Directories to exclude from scanning (repeatable)",
)
@click.option(
    "--mode",
    type=click.Choice(["recall", "strict"]),
    default=None,
    help="Scan mode: recall (default, high sensitivity) or strict (higher thresholds)",
)
@click.option(
    "--exclude-tests/--include-tests",
    default=False,
    help="Exclude test files from scanning (default: include with demoted confidence)",
)
@click.option(
    "--demote-tests/--no-demote-tests",
    default=True,
    help="Reduce confidence for findings in test files (default: enabled)",
)
@click.option(
    "-q", "--quiet",
    is_flag=True,
    help="Quiet mode: suppress banners and spinners, output only results (useful for CI/CD)",
)
@click.option(
    "--fp-reduction/--no-fp-reduction",
    default=True,
    help="Enable heuristic-based false positive filtering (default: enabled)",
)
@click.option(
    "--fp-threshold",
    type=float,
    default=None,
    help="Minimum TP probability to keep findings (0.0-1.0, default: 0.4)",
)
@click.option(
    "--ml-detection/--no-ml-detection",
    default=False,
    help="Enable ML-based prompt injection detection (experimental)",
)
@click.option(
    "--taint-analysis/--no-taint-analysis",
    default=False,
    help="Enable semantic taint analysis through LLM calls (experimental)",
)
@click.option(
    "--ensemble/--no-ensemble",
    default=True,
    help="Combine ML + pattern + taint findings when multiple methods enabled (default: enabled)",
)
def scan(
    path: str,
    output: str,
    output_file: Optional[str],
    severity: str,
    confidence: Optional[float],
    category: tuple,
    verbose: bool,
    audit: bool,
    config: Optional[str],
    dedup: Optional[str],
    exclude_dir: tuple,
    mode: Optional[str],
    exclude_tests: bool,
    demote_tests: bool,
    quiet: bool,
    fp_reduction: bool,
    fp_threshold: Optional[float],
    ml_detection: bool,
    taint_analysis: bool,
    ensemble: bool,
):
    """
    Perform static code analysis for security vulnerabilities.

    Scans Python code for OWASP LLM Top 10 vulnerabilities including:

    \b
      LLM01: Prompt Injection
      LLM02: Insecure Output Handling
      LLM03: Training Data Poisoning
      LLM04: Model Denial of Service
      LLM05: Supply Chain Vulnerabilities
      LLM06: Sensitive Information Disclosure
      LLM07: Insecure Plugin Design
      LLM08: Excessive Agency
      LLM09: Overreliance
      LLM10: Model Theft

    PATH can be a local file/directory or a remote Git URL:

    \b
      - GitHub:    https://github.com/user/repo
      - GitLab:    https://gitlab.com/user/repo
      - Bitbucket: https://bitbucket.org/user/repo

    HTML reports include a Security Posture audit tab by default, showing
    detected security controls and maturity scoring. Use --no-audit to
    disable this feature.

    Examples:

    \b
      aisentry scan ./my_project
      aisentry scan ./app.py -o json -f report.json
      aisentry scan https://github.com/user/llm-app -o html -f report.html
      aisentry scan ./project --category LLM01 LLM02
      aisentry scan ./project -o html --no-audit -f vuln-only.html
    """
    setup_logging(verbose)

    # Validate path - must be a valid local path OR a remote URL
    if not is_remote_url(path) and not Path(path).exists():
        if not quiet:
            console.print(f"[red]Error:[/red] Path does not exist: {path}")
            console.print("\n[dim]For remote repositories, use a full URL:[/dim]")
            console.print("  - https://github.com/user/repo")
            console.print("  - https://gitlab.com/user/repo")
            console.print("  - https://bitbucket.org/user/repo")
        else:
            print(f"Error: Path does not exist: {path}", file=sys.stderr)
        sys.exit(1)

    # Show appropriate panel (unless quiet mode)
    if not quiet:
        if is_remote_url(path):
            console.print(Panel.fit(
                "[bold blue]aisentry[/bold blue] - Remote Repository Scan",
                border_style="blue",
            ))
            console.print(f"\n[cyan]Repository:[/cyan] {path}")
        else:
            console.print(Panel.fit(
                "[bold blue]aisentry[/bold blue] - Static Code Analysis",
                border_style="blue",
            ))

    # Convert categories tuple to list
    categories = list(category) if category else None

    # Build CLI options for config
    cli_options = {}
    if confidence is not None:
        cli_options['global_threshold'] = confidence
    if dedup is not None:
        cli_options['dedup'] = dedup
    if exclude_dir:
        cli_options['exclude_dirs'] = list(exclude_dir)
    if mode is not None:
        cli_options['mode'] = mode
    cli_options['exclude_tests'] = exclude_tests
    cli_options['demote_tests'] = demote_tests
    cli_options['fp_reduction'] = fp_reduction
    if fp_threshold is not None:
        cli_options['fp_threshold'] = fp_threshold
    cli_options['ml_detection'] = ml_detection
    cli_options['taint_analysis'] = taint_analysis
    cli_options['ensemble'] = ensemble

    # Load config with precedence: CLI > env > yaml > defaults
    config_path = Path(config) if config else None
    scan_path = Path(path) if not is_remote_url(path) else None
    scan_config = load_config(
        cli_options=cli_options,
        config_path=config_path,
        scan_path=scan_path,
    )

    # Initialize scanner with config
    scanner = StaticScanner(
        verbose=verbose,
        categories=categories,
        config=scan_config,
    )

    # Run scan with or without progress spinner
    try:
        if quiet:
            result = scanner.scan(path)
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                if is_remote_url(path):
                    task = progress.add_task("Cloning repository...", total=None)
                else:
                    task = progress.add_task("Scanning...", total=None)
                result = scanner.scan(path)
                progress.update(task, description="Scan complete!")
    except FileNotFoundError as e:
        if quiet:
            print(f"Error: {e}", file=sys.stderr)
        else:
            console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except RuntimeError as e:
        if quiet:
            print(f"Error: {e}", file=sys.stderr)
        else:
            console.print(f"[red]Error:[/red] {e}")
            console.print("\n[dim]Make sure git is installed and the repository URL is correct.[/dim]")
        sys.exit(1)
    except Exception as e:
        if quiet:
            print(f"Error during scan: {e}", file=sys.stderr)
        else:
            console.print(f"[red]Error during scan:[/red] {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Filter by severity
    severity_order = ["critical", "high", "medium", "low", "info"]
    min_severity_idx = severity_order.index(severity)
    filtered_findings = [
        f for f in result.findings
        if severity_order.index(f.severity.value.lower()) <= min_severity_idx
    ]
    result.findings = filtered_findings

    # Run audit if enabled and output is HTML
    audit_result = None
    if audit and output == "html":
        try:
            import shutil

            from aisentry.audit import AuditEngine
            from aisentry.core.scanner import clone_repository

            def run_audit():
                nonlocal audit_result
                # Determine audit path
                if is_remote_url(path):
                    temp_dir, success = clone_repository(path)
                    if success:
                        audit_path = Path(temp_dir)
                    else:
                        audit_path = None
                        temp_dir_local = None
                else:
                    audit_path = Path(path)
                    temp_dir_local = None

                if audit_path and audit_path.exists():
                    audit_engine = AuditEngine(verbose=verbose)
                    audit_result = audit_engine.run(audit_path)

                # Cleanup temp directory
                if is_remote_url(path) and 'temp_dir' in dir() and temp_dir:
                    shutil.rmtree(temp_dir, ignore_errors=True)

            if quiet:
                run_audit()
            else:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console,
                ) as progress:
                    task = progress.add_task("Running security audit...", total=None)
                    run_audit()
                    progress.update(task, description="Audit complete!")

        except ImportError:
            if verbose and not quiet:
                console.print("[dim]Audit module not available, skipping security posture audit[/dim]")
        except Exception as e:
            if verbose and not quiet:
                console.print(f"[dim]Audit failed: {e}[/dim]")

    # Generate output
    if output == "json":
        reporter = JSONReporter(verbose=verbose)
        report = reporter.generate_scan_report(result)
    elif output == "html":
        reporter = HTMLReporter(verbose=verbose)
        if audit_result:
            # Use combined tabbed report
            report = reporter.generate_scan_with_audit_report(result, audit_result)
        else:
            report = reporter.generate_scan_report(result)
    elif output == "sarif":
        reporter = SARIFReporter(verbose=verbose)
        report = reporter.generate_scan_report(result)
    else:
        # Text output using rich (skip if quiet)
        if not quiet:
            _print_scan_results(result)
        report = None

    # Save or print report
    if output_file and report:
        Path(output_file).write_text(report, encoding="utf-8")
        if not quiet:
            console.print(f"\n[green]Report saved to:[/green] {output_file}")
    elif report:
        # In quiet mode, print raw report; otherwise use Rich console
        if quiet:
            print(report)
        else:
            console.print(report)


@main.command()
@click.option(
    "-p", "--provider",
    type=click.Choice(list(PROVIDER_MAP.keys())),
    required=True,
    help="LLM provider to test",
)
@click.option(
    "-m", "--model",
    required=True,
    help="Model name (e.g., gpt-4, claude-3-opus, llama2)",
)
@click.option(
    "-e", "--endpoint",
    help="Custom endpoint URL (for 'custom' provider)",
)
@click.option(
    "-t", "--tests",
    multiple=True,
    help="Specific tests to run (default: all)",
)
@click.option(
    "--mode",
    type=click.Choice(["quick", "standard", "comprehensive"]),
    default="standard",
    help="Testing depth (default: standard)",
)
@click.option(
    "-o", "--output",
    type=click.Choice(["text", "json", "html", "sarif"]),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "-f", "--output-file",
    type=click.Path(),
    help="Write output to file",
)
@click.option(
    "--timeout",
    type=int,
    default=30,
    help="Timeout per test in seconds (default: 30)",
)
@click.option(
    "--parallelism",
    type=int,
    default=5,
    help="Maximum concurrent tests (default: 5)",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable verbose output",
)
def test(
    provider: str,
    model: str,
    endpoint: Optional[str],
    tests: tuple,
    mode: str,
    output: str,
    output_file: Optional[str],
    timeout: int,
    parallelism: int,
    verbose: bool,
):
    """
    Perform live security testing on an LLM model.

    Tests models for vulnerabilities including:

    \b
      - Prompt injection
      - Jailbreak attempts
      - Data leakage
      - Hallucination
      - Denial of Service
      - Bias detection
      - Model extraction
      - Adversarial inputs
      - Output manipulation
      - Supply chain risks
      - Behavioral anomalies

    Environment Variables:

    \b
      OPENAI_API_KEY         - For OpenAI provider
      ANTHROPIC_API_KEY      - For Anthropic provider
      AWS_ACCESS_KEY_ID      - For Bedrock provider
      AWS_SECRET_ACCESS_KEY  - For Bedrock provider
      GOOGLE_APPLICATION_CREDENTIALS - For Vertex provider
      AZURE_OPENAI_API_KEY   - For Azure provider
      AZURE_OPENAI_ENDPOINT  - For Azure provider

    Examples:

    \b
      aisentry test -p openai -m gpt-4 --mode quick
      aisentry test -p anthropic -m claude-3-opus -o html -f report.html
      aisentry test -p ollama -m llama2 -t prompt-injection -t jailbreak
    """
    setup_logging(verbose)

    console.print(Panel.fit(
        "[bold blue]aisentry[/bold blue] - Live Model Testing",
        border_style="blue",
    ))

    # Recommend garak for comprehensive live testing
    console.print()
    console.print(Panel(
        "[yellow]Recommendation:[/yellow] For comprehensive LLM red-teaming and live testing, "
        "we recommend [bold cyan]garak[/bold cyan] - a dedicated LLM vulnerability scanner.\n\n"
        "[dim]Install:[/dim] pip install garak\n"
        "[dim]GitHub:[/dim] https://github.com/NVIDIA/garak\n\n"
        "[dim]aisentry's live testing provides basic coverage. garak offers 100+ probes across "
        "many attack categories with active development.[/dim]",
        title="[yellow]Live Testing Note[/yellow]",
        border_style="yellow",
    ))
    console.print()

    # Create provider
    try:
        provider_class = PROVIDER_MAP[provider]
        if provider == "custom":
            if not endpoint:
                console.print("[red]Error:[/red] --endpoint required for custom provider")
                sys.exit(1)
            llm_provider = provider_class(model=model, endpoint=endpoint)
        else:
            llm_provider = provider_class(model=model)
    except ValueError as e:
        console.print(f"[red]Provider error:[/red] {e}")
        console.print("\nMake sure the required environment variable is set.")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error creating provider:[/red] {e}")
        sys.exit(1)

    # Convert tests tuple to list
    test_list = list(tests) if tests else None

    # Show available tests if requested
    if test_list and "list" in test_list:
        _print_available_tests()
        return

    console.print(f"\n[cyan]Provider:[/cyan] {provider}")
    console.print(f"[cyan]Model:[/cyan] {model}")
    console.print(f"[cyan]Mode:[/cyan] {mode}")
    console.print(f"[cyan]Tests:[/cyan] {', '.join(test_list) if test_list else 'all'}")
    console.print()

    # Run tests
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running security tests...", total=None)

        try:
            # Create tester
            tester = LiveTester(
                provider=llm_provider,
                tests=test_list,
                mode=mode,
                parallelism=parallelism,
                timeout=timeout,
                verbose=verbose,
            )

            # Run async tests
            result = asyncio.run(tester.run())
            progress.update(task, description="Tests complete!")

        except ValueError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Error during testing:[/red] {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    # Generate output
    if output == "json":
        reporter = JSONReporter(verbose=verbose)
        report = reporter.generate_test_report(result)
    elif output == "html":
        reporter = HTMLReporter(verbose=verbose)
        report = reporter.generate_test_report(result)
    elif output == "sarif":
        reporter = SARIFReporter(verbose=verbose)
        report = reporter.generate_test_report(result)
    else:
        # Text output using rich
        _print_test_results(result)
        report = None

    # Save or print report
    if output_file and report:
        Path(output_file).write_text(report, encoding="utf-8")
        console.print(f"\n[green]Report saved to:[/green] {output_file}")
    elif report:
        console.print(report)


@main.command("list-tests")
def list_tests():
    """List all available security tests."""
    _print_available_tests()


@main.command()
@click.argument("path", type=str)
@click.option(
    "-o", "--output",
    type=click.Choice(["text", "json", "html"]),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "-f", "--output-file",
    type=click.Path(),
    help="Write output to file",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable verbose output",
)
def audit(
    path: str,
    output: str,
    output_file: Optional[str],
    verbose: bool,
):
    """
    Perform security posture audit on a codebase.

    Automatically detects security controls and calculates maturity scores
    across multiple categories:

    \b
      - Prompt Security: Sanitization, rate limiting, validation
      - Model Security: Access control, versioning, dependency scanning
      - Data Privacy: PII detection, encryption, audit logging
      - OWASP LLM Top 10: Coverage of all 10 vulnerability categories
      - Blue Team Ops: Monitoring, drift detection, incident response
      - Governance: Explainability, bias detection, compliance

    Unlike 'scan' which finds vulnerabilities, 'audit' evaluates what
    security controls ARE implemented in your codebase.

    PATH can be a local file/directory or a remote Git URL:

    \b
      - GitHub:    https://github.com/user/repo
      - GitLab:    https://gitlab.com/user/repo
      - Bitbucket: https://bitbucket.org/user/repo

    Examples:

    \b
      aisentry audit ./my-project
      aisentry audit ./my-project -o html -f audit-report.html
      aisentry audit https://github.com/user/repo -o html -f audit.html
    """
    setup_logging(verbose)

    # Import required modules
    import shutil

    from aisentry.audit import AuditEngine
    from aisentry.core.scanner import clone_repository, is_remote_url

    # Validate path
    is_remote = is_remote_url(path)
    if not is_remote and not Path(path).exists():
        console.print(f"[red]Error:[/red] Path does not exist: {path}")
        console.print("\n[dim]For remote repositories, use a full URL:[/dim]")
        console.print("  - https://github.com/user/repo")
        console.print("  - https://gitlab.com/user/repo")
        console.print("  - https://bitbucket.org/user/repo")
        sys.exit(1)

    # Show appropriate panel
    if is_remote:
        console.print(Panel.fit(
            "[bold blue]aisentry[/bold blue] - Remote Repository Audit",
            border_style="blue",
        ))
        console.print(f"\n[cyan]Repository:[/cyan] {path}")
    else:
        console.print(Panel.fit(
            "[bold blue]aisentry[/bold blue] - Security Posture Audit",
            border_style="blue",
        ))

    # Initialize engine
    engine = AuditEngine(verbose=verbose)
    temp_dir = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Clone if remote
        if is_remote:
            task = progress.add_task("Cloning repository...", total=None)
            temp_dir, success = clone_repository(path)
            if not success:
                console.print("[red]Error:[/red] Failed to clone repository")
                console.print("\n[dim]Make sure git is installed and the repository URL is correct.[/dim]")
                sys.exit(1)
            audit_path = Path(temp_dir)
            progress.update(task, description="Repository cloned!")
        else:
            audit_path = Path(path)

        task = progress.add_task("Running security audit...", total=None)

        try:
            result = engine.run(audit_path)
            progress.update(task, description="Audit complete!")
        except Exception as e:
            console.print(f"[red]Error during audit:[/red] {e}")
            if verbose:
                import traceback
                traceback.print_exc()
            # Cleanup temp directory
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)
            sys.exit(1)

    # Cleanup temp directory
    if temp_dir:
        shutil.rmtree(temp_dir, ignore_errors=True)

    # Generate output
    if output == "json":
        report = engine.generate_report(result, format="json")
    elif output == "html":
        report = engine.generate_report(result, format="html")
    else:
        # Text output
        engine.print_summary(result)
        report = None

    # Save or print report
    if output_file and report:
        Path(output_file).write_text(report, encoding="utf-8")
        console.print(f"\n[green]Report saved to:[/green] {output_file}")
    elif report:
        console.print(report)


def _print_scan_results(result):
    """Print scan results using rich formatting."""
    # Summary table
    summary_table = Table(title="Scan Summary", show_header=False)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Target", result.target_path)
    summary_table.add_row("Files Scanned", str(result.files_scanned))
    summary_table.add_row("Security Score", f"{result.overall_score:.1f}/100")
    summary_table.add_row("Confidence", f"{result.confidence*100:.0f}%")
    summary_table.add_row("Duration", f"{result.duration_seconds:.2f}s")
    summary_table.add_row("Total Findings", str(len(result.findings)))

    console.print(summary_table)

    # Severity breakdown
    if result.findings:
        severity_counts = {}
        for f in result.findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        console.print("\n[bold]Severity Breakdown:[/bold]")
        for sev, count in sorted(severity_counts.items()):
            color = _get_severity_color(sev)
            console.print(f"  [{color}]{sev}:[/{color}] {count}")

    # Findings
    if result.findings:
        console.print("\n[bold]Findings:[/bold]")
        for i, finding in enumerate(result.findings[:10], 1):
            color = _get_severity_color(finding.severity.value)
            console.print(f"\n{i}. [{color}][{finding.severity.value}][/{color}] {finding.title}")
            console.print(f"   [dim]{finding.file_path}:{finding.line_number}[/dim]")
            console.print(f"   {finding.description[:100]}...")

        if len(result.findings) > 10:
            console.print(f"\n[dim]... and {len(result.findings) - 10} more findings[/dim]")


def _print_test_results(result):
    """Print test results using rich formatting."""
    # Summary table
    summary_table = Table(title="Test Summary", show_header=False)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Provider", result.provider)
    summary_table.add_row("Model", result.model)
    summary_table.add_row("Mode", result.mode)
    summary_table.add_row("Security Score", f"{result.overall_score:.1f}/100")
    summary_table.add_row("Confidence", f"{result.confidence*100:.0f}%")
    summary_table.add_row("Tests Run", str(result.tests_run))
    summary_table.add_row("Tests Passed", str(result.tests_passed))
    summary_table.add_row("Pass Rate", f"{result.tests_passed/max(result.tests_run,1)*100:.0f}%")
    summary_table.add_row("Duration", f"{result.duration_seconds:.2f}s")
    summary_table.add_row("Vulnerabilities", str(len(result.vulnerabilities)))

    console.print(summary_table)

    # Detector results
    if result.detector_results:
        console.print("\n[bold]Detector Results:[/bold]")
        det_table = Table()
        det_table.add_column("Detector", style="cyan")
        det_table.add_column("Score", justify="right")
        det_table.add_column("Tests", justify="right")
        det_table.add_column("Issues", justify="right")

        for det in result.detector_results:
            score_style = "green" if det.score >= 70 else ("yellow" if det.score >= 40 else "red")
            det_table.add_row(
                det.detector_name,
                f"[{score_style}]{det.score:.0f}[/{score_style}]",
                f"{det.tests_passed}/{det.tests_run}",
                str(len(det.vulnerabilities)),
            )

        console.print(det_table)

    # Vulnerabilities
    if result.vulnerabilities:
        console.print("\n[bold]Vulnerabilities Found:[/bold]")
        for i, vuln in enumerate(result.vulnerabilities[:10], 1):
            color = _get_severity_color(vuln.severity.value)
            console.print(f"\n{i}. [{color}][{vuln.severity.value}][/{color}] {vuln.title}")
            console.print(f"   {vuln.description[:100]}...")

        if len(result.vulnerabilities) > 10:
            console.print(f"\n[dim]... and {len(result.vulnerabilities) - 10} more vulnerabilities[/dim]")


def _print_available_tests():
    """Print available security tests."""
    console.print("\n[bold]Available Security Tests:[/bold]\n")

    tests_table = Table()
    tests_table.add_column("Test Name", style="cyan")
    tests_table.add_column("Description")

    for test_name in DETECTOR_REGISTRY.keys():
        desc = LiveTester.get_test_description(test_name)
        tests_table.add_row(test_name, desc)

    console.print(tests_table)
    console.print("\n[dim]Use -t/--tests to specify tests, e.g., -t prompt-injection -t jailbreak[/dim]")


def _get_severity_color(severity: str) -> str:
    """Get rich color for severity level."""
    colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }
    return colors.get(severity, "white")


# =============================================================================
# ML Training Commands
# =============================================================================

@main.group()
def ml():
    """
    Machine learning model training and evaluation.

    Commands for training the ML-based prompt injection classifier
    and evaluating detector performance.
    """
    pass


@ml.command("train")
@click.option(
    "-n", "--num-samples",
    type=int,
    default=5000,
    help="Number of synthetic samples to generate (default: 5000)",
)
@click.option(
    "-o", "--output",
    type=click.Path(),
    default="prompt_injection_model.pkl",
    help="Output path for trained model",
)
@click.option(
    "--export-onnx/--no-export-onnx",
    default=False,
    help="Also export model to ONNX format",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable verbose output",
)
def ml_train(num_samples: int, output: str, export_onnx: bool, verbose: bool):
    """
    Train the ML-based prompt injection classifier.

    Generates synthetic training data and trains a LightGBM classifier
    to detect prompt injection vulnerabilities.

    Example:
        aisentry ml train -n 10000 -o model.pkl --export-onnx
    """
    setup_logging(verbose)

    try:
        from aisentry.ml.training.trainer import PromptInjectionTrainer
    except ImportError as e:
        console.print(f"[red]Training dependencies not available: {e}[/red]")
        console.print("[dim]Install with: pip install lightgbm scikit-learn[/dim]")
        sys.exit(1)

    console.print(Panel.fit(
        f"[bold]Training ML Classifier[/bold]\n"
        f"Samples: {num_samples}\n"
        f"Output: {output}",
        title="ML Training",
    ))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Generate synthetic data
        task = progress.add_task("Generating synthetic data...", total=None)
        trainer = PromptInjectionTrainer()
        samples = trainer.generate_synthetic_data(num_samples=num_samples)
        progress.update(task, description=f"Generated {len(samples)} samples")

        # Load samples
        task = progress.add_task("Extracting features...", total=None)
        trainer.load_samples(samples)
        progress.update(task, description="Features extracted")

        # Train
        task = progress.add_task("Training classifiers...", total=None)
        vuln_metrics, attack_metrics = trainer.train(cross_validate=True)
        progress.update(task, description="Training complete")

        # Save model
        task = progress.add_task("Saving model...", total=None)
        trainer.save_model(output)
        progress.update(task, description=f"Model saved to {output}")

        # Export ONNX if requested
        if export_onnx:
            task = progress.add_task("Exporting ONNX...", total=None)
            onnx_path = output.replace('.pkl', '.onnx')
            try:
                trainer.export_onnx(onnx_path)
                progress.update(task, description=f"ONNX exported to {onnx_path}")
            except ImportError:
                progress.update(task, description="ONNX export skipped (dependencies not available)")

    # Print results
    console.print("\n[bold green]Training Results[/bold green]")

    results_table = Table(title="Vulnerability Classifier")
    results_table.add_column("Metric", style="cyan")
    results_table.add_column("Value", justify="right")

    results_table.add_row("Precision", f"{vuln_metrics.precision:.3f}")
    results_table.add_row("Recall", f"{vuln_metrics.recall:.3f}")
    results_table.add_row("F1 Score", f"{vuln_metrics.f1_score:.3f}")
    if vuln_metrics.roc_auc:
        results_table.add_row("ROC AUC", f"{vuln_metrics.roc_auc:.3f}")
    if vuln_metrics.cross_val_scores is not None:
        import numpy as np
        results_table.add_row("Cross-Val F1", f"{np.mean(vuln_metrics.cross_val_scores):.3f} ± {np.std(vuln_metrics.cross_val_scores):.3f}")

    console.print(results_table)

    # Feature importance
    console.print("\n[bold]Top Feature Importance[/bold]")
    for name, importance in trainer.get_feature_importance(top_n=5).items():
        console.print(f"  {name}: {importance:.3f}")


@ml.command("evaluate")
@click.argument("benchmark_dir", type=click.Path(exists=True))
@click.option(
    "-o", "--output",
    type=click.Path(),
    help="Save report to file",
)
@click.option(
    "--compare/--no-compare",
    default=True,
    help="Compare all detection methods",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable verbose output",
)
def ml_evaluate(benchmark_dir: str, output: Optional[str], compare: bool, verbose: bool):
    """
    Evaluate detectors against benchmark dataset.

    Runs pattern-based, ML, and semantic taint detectors against
    labeled benchmark files and calculates precision/recall/F1.

    Example:
        aisentry ml evaluate benchmarks/ -o report.md
    """
    setup_logging(verbose)

    from aisentry.evaluation import BenchmarkRunner, SecurityMetrics

    console.print(Panel.fit(
        f"[bold]Evaluating Detectors[/bold]\n"
        f"Benchmark: {benchmark_dir}",
        title="Evaluation",
    ))

    runner = BenchmarkRunner(benchmark_dir)

    if not runner.ground_truth:
        console.print("[yellow]Warning: No ground_truth.json found. Generating template...[/yellow]")
        template_path = Path(benchmark_dir) / "ground_truth.json"
        runner.generate_ground_truth_template(str(template_path))
        console.print(f"[dim]Template saved to {template_path}. Please label the files and re-run.[/dim]")
        return

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running evaluation...", total=None)
        results = runner.run_evaluation()
        progress.update(task, description="Evaluation complete")

    # Print comparison table
    if compare:
        console.print("\n[bold]Method Comparison[/bold]")
        comparison = SecurityMetrics.compare_methods(results, baseline_name='pattern_only')
        console.print(comparison)

    # Print detailed results
    for name, metrics in results.items():
        console.print(f"\n[bold cyan]{name}[/bold cyan]")
        console.print(f"  Precision: {metrics.precision:.3f}")
        console.print(f"  Recall: {metrics.recall:.3f}")
        console.print(f"  F1: {metrics.f1_score:.3f}")
        console.print(f"  Critical Recall: {metrics.critical_recall:.3f}")
        console.print(f"  TP: {metrics.true_positives}, FP: {metrics.false_positives}")

    # Save report if requested
    if output:
        report = runner.create_comparison_report(results, output)
        console.print(f"\n[green]Report saved to {output}[/green]")


@ml.command("generate-benchmarks")
@click.argument("output_dir", type=click.Path())
@click.option(
    "-n", "--num-samples",
    type=int,
    default=10,
    help="Samples per category (default: 10)",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    help="Enable verbose output",
)
def ml_generate_benchmarks(output_dir: str, num_samples: int, verbose: bool):
    """
    Generate sample benchmark dataset for testing.

    Creates synthetic vulnerable and safe code samples with
    ground truth labels for evaluation.

    Example:
        aisentry ml generate-benchmarks benchmarks/ -n 20
    """
    setup_logging(verbose)

    from aisentry.evaluation.benchmark_runner import create_sample_benchmarks

    console.print(Panel.fit(
        f"[bold]Generating Benchmarks[/bold]\n"
        f"Output: {output_dir}\n"
        f"Samples per category: {num_samples}",
        title="Benchmark Generation",
    ))

    create_sample_benchmarks(output_dir)

    console.print(f"\n[green]Benchmarks created in {output_dir}[/green]")
    console.print("[dim]Run evaluation with: aisentry ml evaluate {output_dir}[/dim]")


if __name__ == "__main__":
    main()
