"""
HTML reporter for audit results.
"""

from pathlib import Path

from ..models import AuditResult, CategoryScore, ControlEvidence


class HTMLAuditReporter:
    """Generate HTML reports from audit results."""

    def generate(self, result: AuditResult) -> str:
        """
        Generate HTML report from audit result.

        Args:
            result: Audit result to convert

        Returns:
            HTML string
        """
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Security Audit Report</title>
    <style>
        {self._get_styles()}
    </style>
</head>
<body>
    <div class="container">
        {self._render_header(result)}
        {self._render_summary(result)}
        {self._render_categories(result)}
        {self._render_recommendations(result)}
        {self._render_footer(result)}
    </div>
</body>
</html>"""

    def save(self, result: AuditResult, output_path: Path) -> None:
        """Save audit result to HTML file."""
        output_path.write_text(self.generate(result))

    def _get_styles(self) -> str:
        """Get CSS styles for the report."""
        return """
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f8fafc;
            color: #1e293b;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .header h1 {
            font-size: 2rem;
            color: #0f172a;
            margin-bottom: 8px;
        }
        .header .subtitle {
            color: #64748b;
            font-size: 1rem;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .card {
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .score-card {
            text-align: center;
        }
        .score-value {
            font-size: 3rem;
            font-weight: 700;
            background: linear-gradient(135deg, #f97316, #ea580c);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .score-label {
            color: #64748b;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .maturity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 500;
            margin-top: 8px;
        }
        .maturity-initial { background: #fee2e2; color: #dc2626; }
        .maturity-developing { background: #ffedd5; color: #ea580c; }
        .maturity-defined { background: #fef3c7; color: #d97706; }
        .maturity-managed { background: #d1fae5; color: #059669; }
        .maturity-optimizing { background: #cffafe; color: #0891b2; }
        .categories {
            margin-bottom: 40px;
        }
        .categories h2 {
            font-size: 1.5rem;
            margin-bottom: 20px;
            color: #0f172a;
        }
        .category-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
        }
        .category-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }
        .category-name {
            font-weight: 600;
            color: #0f172a;
        }
        .category-score {
            font-weight: 700;
            color: #f97316;
        }
        .progress-bar {
            height: 8px;
            background: #e2e8f0;
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 16px;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #f97316, #ea580c);
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        .controls-list {
            list-style: none;
        }
        .control-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #f1f5f9;
        }
        .control-item:last-child {
            border-bottom: none;
        }
        .control-name {
            font-size: 0.875rem;
            color: #475569;
        }
        .control-status {
            font-size: 0.75rem;
            padding: 2px 8px;
            border-radius: 10px;
            font-weight: 500;
        }
        .status-detected { background: #d1fae5; color: #059669; }
        .status-missing { background: #fee2e2; color: #dc2626; }
        .status-partial { background: #fef3c7; color: #d97706; }
        .recommendations {
            margin-bottom: 40px;
        }
        .recommendations h2 {
            font-size: 1.5rem;
            margin-bottom: 20px;
            color: #0f172a;
        }
        .rec-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .rec-item {
            background: white;
            border-radius: 8px;
            padding: 16px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid;
        }
        .rec-critical { border-color: #dc2626; }
        .rec-high { border-color: #ea580c; }
        .rec-medium { border-color: #d97706; }
        .rec-low { border-color: #059669; }
        .rec-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .rec-title {
            font-weight: 600;
            color: #0f172a;
        }
        .rec-priority {
            font-size: 0.75rem;
            padding: 2px 8px;
            border-radius: 10px;
            font-weight: 500;
            text-transform: uppercase;
        }
        .priority-critical { background: #fee2e2; color: #dc2626; }
        .priority-high { background: #ffedd5; color: #ea580c; }
        .priority-medium { background: #fef3c7; color: #d97706; }
        .priority-low { background: #d1fae5; color: #059669; }
        .rec-description {
            color: #64748b;
            font-size: 0.875rem;
        }
        .footer {
            text-align: center;
            color: #94a3b8;
            font-size: 0.875rem;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
        }
        """

    def _render_header(self, result: AuditResult) -> str:
        """Render report header."""
        return f"""
        <div class="header">
            <h1>AI Security Audit Report</h1>
            <p class="subtitle">Project: {result.project_path} | {result.timestamp.strftime('%Y-%m-%d %H:%M')}</p>
        </div>
        """

    def _render_summary(self, result: AuditResult) -> str:
        """Render summary section."""
        maturity_class = f"maturity-{result.maturity_level.value.lower()}"
        return f"""
        <div class="summary">
            <div class="card score-card">
                <div class="score-value">{result.overall_score:.0f}</div>
                <div class="score-label">Overall Score</div>
                <span class="maturity-badge {maturity_class}">{result.maturity_level.value}</span>
            </div>
            <div class="card score-card">
                <div class="score-value">{result.detected_controls_count}</div>
                <div class="score-label">Controls Detected</div>
                <span class="maturity-badge" style="background: #f1f5f9; color: #64748b;">of {result.total_controls_count}</span>
            </div>
            <div class="card score-card">
                <div class="score-value">{result.files_scanned}</div>
                <div class="score-label">Files Scanned</div>
                <span class="maturity-badge" style="background: #f1f5f9; color: #64748b;">{result.scan_duration_seconds:.1f}s</span>
            </div>
            <div class="card score-card">
                <div class="score-value">{len(result.recommendations)}</div>
                <div class="score-label">Recommendations</div>
            </div>
        </div>
        """

    def _render_categories(self, result: AuditResult) -> str:
        """Render categories section."""
        cards = ""
        for cat_id, cat_score in result.categories.items():
            cards += self._render_category_card(cat_score)

        return f"""
        <div class="categories">
            <h2>Category Scores</h2>
            <div class="category-grid">
                {cards}
            </div>
        </div>
        """

    def _render_category_card(self, cat: CategoryScore) -> str:
        """Render a single category card."""
        controls_html = ""
        for control in cat.controls:
            status_class = "status-detected" if control.detected else "status-missing"
            if control.detected and control.score < 50:
                status_class = "status-partial"
            status_text = control.level.value.title() if control.detected else "Missing"

            controls_html += f"""
            <li class="control-item">
                <span class="control-name">{control.control_name}</span>
                <span class="control-status {status_class}">{status_text}</span>
            </li>
            """

        return f"""
        <div class="category-card">
            <div class="category-header">
                <span class="category-name">{cat.category_name}</span>
                <span class="category-score">{cat.score:.0f}/100</span>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {cat.percentage}%"></div>
            </div>
            <ul class="controls-list">
                {controls_html}
            </ul>
        </div>
        """

    def _render_recommendations(self, result: AuditResult) -> str:
        """Render recommendations section."""
        if not result.recommendations:
            return ""

        recs_html = ""
        for rec in result.recommendations[:10]:  # Limit to top 10
            priority_class = f"priority-{rec.priority}"
            rec_border = f"rec-{rec.priority}"
            recs_html += f"""
            <div class="rec-item {rec_border}">
                <div class="rec-header">
                    <span class="rec-title">{rec.title}</span>
                    <span class="rec-priority {priority_class}">{rec.priority}</span>
                </div>
                <p class="rec-description">{rec.remediation}</p>
            </div>
            """

        return f"""
        <div class="recommendations">
            <h2>Top Recommendations</h2>
            <div class="rec-list">
                {recs_html}
            </div>
        </div>
        """

    def _render_footer(self, result: AuditResult) -> str:
        """Render report footer."""
        return f"""
        <div class="footer">
            <p>Generated by AI Security CLI | Audit ID: {result.audit_id}</p>
        </div>
        """
