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
    <script>
        {self._get_scripts()}
    </script>
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
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px;
            cursor: pointer;
            user-select: none;
            transition: background 0.2s;
        }
        .category-header:hover {
            background: #f8fafc;
        }
        .category-header-left {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .category-name {
            font-weight: 600;
            color: #0f172a;
        }
        .category-score {
            font-weight: 700;
            color: #f97316;
        }
        .accordion-icon {
            width: 20px;
            height: 20px;
            transition: transform 0.3s ease;
            color: #64748b;
        }
        .category-card.open .accordion-icon {
            transform: rotate(180deg);
        }
        .progress-bar {
            height: 4px;
            background: #e2e8f0;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #f97316, #ea580c);
            transition: width 0.3s ease;
        }
        .category-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }
        .category-card.open .category-content {
            max-height: 2000px;
            transition: max-height 0.5s ease-in;
        }
        .controls-list {
            list-style: none;
            padding: 0 20px 20px;
        }
        .control-item {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding: 12px 0;
            border-bottom: 1px solid #f1f5f9;
        }
        .control-item:last-child {
            border-bottom: none;
        }
        .control-info {
            flex: 1;
        }
        .control-name {
            font-size: 0.875rem;
            color: #0f172a;
            font-weight: 500;
        }
        .control-description {
            font-size: 0.75rem;
            color: #64748b;
            margin-top: 2px;
        }
        .control-status {
            font-size: 0.75rem;
            padding: 2px 8px;
            border-radius: 10px;
            font-weight: 500;
            white-space: nowrap;
            margin-left: 12px;
        }
        .status-detected { background: #d1fae5; color: #059669; }
        .status-missing { background: #fee2e2; color: #dc2626; }
        .status-partial { background: #fef3c7; color: #d97706; }
        .category-stats {
            display: flex;
            gap: 16px;
            padding: 12px 20px;
            background: #f8fafc;
            border-top: 1px solid #e2e8f0;
            font-size: 0.75rem;
            color: #64748b;
        }
        .stat-item {
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .stat-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        .stat-dot.detected { background: #059669; }
        .stat-dot.partial { background: #d97706; }
        .stat-dot.missing { background: #dc2626; }

        /* Recommendations Accordion */
        .recommendations {
            margin-bottom: 40px;
        }
        .recommendations h2 {
            font-size: 1.5rem;
            margin-bottom: 20px;
            color: #0f172a;
        }
        .rec-accordion {
            background: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            overflow: hidden;
            margin-bottom: 12px;
        }
        .rec-accordion-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            cursor: pointer;
            user-select: none;
            border-left: 4px solid;
            transition: background 0.2s;
        }
        .rec-accordion-header:hover {
            background: #f8fafc;
        }
        .rec-accordion.critical .rec-accordion-header { border-color: #dc2626; }
        .rec-accordion.high .rec-accordion-header { border-color: #ea580c; }
        .rec-accordion.medium .rec-accordion-header { border-color: #d97706; }
        .rec-accordion.low .rec-accordion-header { border-color: #059669; }
        .rec-accordion-title {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .rec-accordion-title h3 {
            font-size: 1rem;
            font-weight: 600;
            color: #0f172a;
        }
        .rec-count {
            font-size: 0.75rem;
            padding: 2px 8px;
            border-radius: 10px;
            font-weight: 500;
        }
        .rec-count.critical { background: #fee2e2; color: #dc2626; }
        .rec-count.high { background: #ffedd5; color: #ea580c; }
        .rec-count.medium { background: #fef3c7; color: #d97706; }
        .rec-count.low { background: #d1fae5; color: #059669; }
        .rec-accordion-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }
        .rec-accordion.open .rec-accordion-content {
            max-height: 2000px;
            transition: max-height 0.5s ease-in;
        }
        .rec-accordion.open .accordion-icon {
            transform: rotate(180deg);
        }
        .rec-list {
            padding: 0 20px 20px;
        }
        .rec-item {
            padding: 16px;
            background: #f8fafc;
            border-radius: 8px;
            margin-bottom: 12px;
        }
        .rec-item:last-child {
            margin-bottom: 0;
        }
        .rec-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 8px;
        }
        .rec-title {
            font-weight: 600;
            color: #0f172a;
            font-size: 0.9rem;
        }
        .rec-category {
            font-size: 0.7rem;
            padding: 2px 6px;
            border-radius: 4px;
            background: #e2e8f0;
            color: #64748b;
            white-space: nowrap;
        }
        .rec-description {
            color: #64748b;
            font-size: 0.85rem;
            line-height: 1.5;
        }

        /* Evidence Section */
        .evidence-section {
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px solid #e2e8f0;
        }
        .evidence-toggle {
            font-size: 0.75rem;
            color: #f97316;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }
        .evidence-toggle:hover {
            text-decoration: underline;
        }
        .evidence-list {
            display: none;
            margin-top: 8px;
        }
        .evidence-list.show {
            display: block;
        }
        .evidence-item {
            font-size: 0.75rem;
            color: #64748b;
            padding: 4px 8px;
            background: #f1f5f9;
            border-radius: 4px;
            margin-bottom: 4px;
            font-family: monospace;
        }

        .footer {
            text-align: center;
            color: #94a3b8;
            font-size: 0.875rem;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
        }

        /* Expand/Collapse All */
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .section-header h2 {
            margin-bottom: 0;
        }
        .expand-toggle {
            font-size: 0.8rem;
            color: #f97316;
            cursor: pointer;
            padding: 4px 12px;
            border: 1px solid #f97316;
            border-radius: 6px;
            background: white;
            transition: all 0.2s;
        }
        .expand-toggle:hover {
            background: #f97316;
            color: white;
        }
        """

    def _get_scripts(self) -> str:
        """Get JavaScript for accordion functionality."""
        return """
        // Accordion functionality for categories
        document.querySelectorAll('.category-header').forEach(header => {
            header.addEventListener('click', () => {
                const card = header.parentElement;
                card.classList.toggle('open');
            });
        });

        // Accordion functionality for recommendations
        document.querySelectorAll('.rec-accordion-header').forEach(header => {
            header.addEventListener('click', () => {
                const accordion = header.parentElement;
                accordion.classList.toggle('open');
            });
        });

        // Evidence toggle
        document.querySelectorAll('.evidence-toggle').forEach(toggle => {
            toggle.addEventListener('click', (e) => {
                e.stopPropagation();
                const list = toggle.nextElementSibling;
                list.classList.toggle('show');
                toggle.textContent = list.classList.contains('show') ? 'Hide Evidence' : 'Show Evidence';
            });
        });

        // Expand/Collapse all categories
        document.getElementById('toggle-categories')?.addEventListener('click', (e) => {
            const cards = document.querySelectorAll('.category-card');
            const allOpen = [...cards].every(card => card.classList.contains('open'));
            cards.forEach(card => {
                if (allOpen) {
                    card.classList.remove('open');
                } else {
                    card.classList.add('open');
                }
            });
            e.target.textContent = allOpen ? 'Expand All' : 'Collapse All';
        });

        // Expand/Collapse all recommendations
        document.getElementById('toggle-recommendations')?.addEventListener('click', (e) => {
            const accordions = document.querySelectorAll('.rec-accordion');
            const allOpen = [...accordions].every(acc => acc.classList.contains('open'));
            accordions.forEach(acc => {
                if (allOpen) {
                    acc.classList.remove('open');
                } else {
                    acc.classList.add('open');
                }
            });
            e.target.textContent = allOpen ? 'Expand All' : 'Collapse All';
        });

        // Open critical recommendations by default
        document.querySelectorAll('.rec-accordion.critical, .rec-accordion.high').forEach(acc => {
            acc.classList.add('open');
        });
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
        """Render categories section with accordions."""
        cards = ""
        for cat_id, cat_score in result.categories.items():
            cards += self._render_category_card(cat_score)

        return f"""
        <div class="categories">
            <div class="section-header">
                <h2>Category Scores</h2>
                <button class="expand-toggle" id="toggle-categories">Expand All</button>
            </div>
            <div class="category-grid">
                {cards}
            </div>
        </div>
        """

    def _render_category_card(self, cat: CategoryScore) -> str:
        """Render a single category card with accordion."""
        controls_html = ""
        detected_count = 0
        partial_count = 0
        missing_count = 0

        for control in cat.controls:
            if control.detected:
                if control.score >= 50:
                    detected_count += 1
                    status_class = "status-detected"
                    status_text = control.level.value.title()
                else:
                    partial_count += 1
                    status_class = "status-partial"
                    status_text = "Partial"
            else:
                missing_count += 1
                status_class = "status-missing"
                status_text = "Missing"

            # Get description from control if available
            description = getattr(control, 'description', '') or ''

            controls_html += f"""
            <li class="control-item">
                <div class="control-info">
                    <span class="control-name">{control.control_id}: {control.control_name}</span>
                    {f'<div class="control-description">{description}</div>' if description else ''}
                </div>
                <span class="control-status {status_class}">{status_text}</span>
            </li>
            """

        accordion_icon = """<svg class="accordion-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
        </svg>"""

        return f"""
        <div class="category-card">
            <div class="category-header">
                <div class="category-header-left">
                    <span class="category-name">{cat.category_name}</span>
                </div>
                <div style="display: flex; align-items: center; gap: 12px;">
                    <span class="category-score">{cat.score:.0f}/100</span>
                    {accordion_icon}
                </div>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {cat.percentage}%"></div>
            </div>
            <div class="category-content">
                <ul class="controls-list">
                    {controls_html}
                </ul>
                <div class="category-stats">
                    <span class="stat-item"><span class="stat-dot detected"></span> {detected_count} Detected</span>
                    <span class="stat-item"><span class="stat-dot partial"></span> {partial_count} Partial</span>
                    <span class="stat-item"><span class="stat-dot missing"></span> {missing_count} Missing</span>
                </div>
            </div>
        </div>
        """

    def _render_recommendations(self, result: AuditResult) -> str:
        """Render recommendations section with priority-grouped accordions."""
        if not result.recommendations:
            return ""

        # Group recommendations by priority
        priority_groups = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }

        for rec in result.recommendations:
            priority = rec.priority.lower()
            if priority in priority_groups:
                priority_groups[priority].append(rec)
            else:
                priority_groups['low'].append(rec)

        accordion_icon = """<svg class="accordion-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
        </svg>"""

        accordions_html = ""
        priority_labels = {
            'critical': 'Critical Priority',
            'high': 'High Priority',
            'medium': 'Medium Priority',
            'low': 'Low Priority'
        }

        for priority, recs in priority_groups.items():
            if not recs:
                continue

            recs_html = ""
            for rec in recs:
                category = getattr(rec, 'category', '') or ''
                recs_html += f"""
                <div class="rec-item">
                    <div class="rec-header">
                        <span class="rec-title">{rec.title}</span>
                        {f'<span class="rec-category">{category}</span>' if category else ''}
                    </div>
                    <p class="rec-description">{rec.remediation}</p>
                </div>
                """

            accordions_html += f"""
            <div class="rec-accordion {priority}">
                <div class="rec-accordion-header">
                    <div class="rec-accordion-title">
                        <h3>{priority_labels[priority]}</h3>
                        <span class="rec-count {priority}">{len(recs)} items</span>
                    </div>
                    {accordion_icon}
                </div>
                <div class="rec-accordion-content">
                    <div class="rec-list">
                        {recs_html}
                    </div>
                </div>
            </div>
            """

        return f"""
        <div class="recommendations">
            <div class="section-header">
                <h2>Recommendations</h2>
                <button class="expand-toggle" id="toggle-recommendations">Collapse All</button>
            </div>
            {accordions_html}
        </div>
        """

    def _render_footer(self, result: AuditResult) -> str:
        """Render report footer."""
        return f"""
        <div class="footer">
            <p>Generated by AI Security CLI | Audit ID: {result.audit_id} | {result.total_controls_count} Controls Evaluated</p>
        </div>
        """
