"""
SQL Injection Detector

Lightweight detector for SQL injection via string formatting.
No external dependencies - pure regex/AST patterns.

Catches:
- f-strings in execute() calls
- .format() in SQL queries
- String concatenation in SQL
- % formatting in SQL
"""

import re
from typing import Any, Dict, List

from aisentry.models.finding import Finding, Severity
from aisentry.static_detectors.base_detector import BaseDetector


class SQLInjectionDetector(BaseDetector):
    """Detect SQL injection vulnerabilities."""

    detector_id = "SQLI"
    name = "SQL Injection"
    default_confidence_threshold = 0.7

    # SQL execution patterns
    SQL_EXEC_PATTERN = re.compile(
        r'\.(execute|executemany|executescript|raw|extra)\s*\(',
        re.IGNORECASE
    )

    # SQL statement patterns (specific to reduce FPs on log messages)
    SQL_STATEMENT_PATTERNS = [
        re.compile(r'\bSELECT\b.*\bFROM\b', re.IGNORECASE | re.DOTALL),
        re.compile(r'\bINSERT\b.*\bINTO\b', re.IGNORECASE | re.DOTALL),
        re.compile(r'\bUPDATE\b.*\bSET\b', re.IGNORECASE | re.DOTALL),
        re.compile(r'\bDELETE\b.*\bFROM\b', re.IGNORECASE | re.DOTALL),
        re.compile(r'\bCREATE\b.*\b(TABLE|INDEX)\b', re.IGNORECASE | re.DOTALL),
        re.compile(r'\bDROP\b.*\b(TABLE|INDEX)\b', re.IGNORECASE | re.DOTALL),
    ]

    # Lines to skip (log/print statements)
    SKIP_LINE_PATTERNS = re.compile(
        r'^\s*(logger\.|logging\.|print\(|#|.*\.debug\(|.*\.info\(|.*\.warning\(|.*\.error\()'
    )

    # Safe patterns - parameterized queries
    SAFE_PATTERNS = [
        r'execute\s*\([^,]+,\s*[\(\[\{]',  # execute(query, (params,))
        r'execute\s*\([^,]+,\s*\w+\s*\)',   # execute(query, params)
        r'%s.*,\s*\(',                       # %s with tuple params
    ]

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Find SQL injection vulnerabilities."""
        findings = []
        file_path = parsed_data.get('file_path', 'unknown')
        source_lines = parsed_data.get('source_lines', [])
        source_code = '\n'.join(source_lines)

        seen_lines = set()

        def is_near_seen(line: int) -> bool:
            """Check if line or adjacent lines already seen."""
            return any(abs(line - s) <= 1 for s in seen_lines)

        # Method 1: Find execute() calls with inline SQL construction
        for match in self.SQL_EXEC_PATTERN.finditer(source_code):
            start_pos = match.start()
            line_num = source_code[:start_pos].count('\n') + 1

            context_start = source_code.rfind('\n', 0, start_pos) + 1
            context_end = self._find_statement_end(source_code, match.end())
            statement = source_code[context_start:context_end]

            if self._is_parameterized(statement):
                continue

            issues = self._check_unsafe_patterns(statement)
            if issues and not is_near_seen(line_num):
                seen_lines.add(line_num)
                findings.append(self._create_finding(file_path, line_num, issues, source_lines))

        # Method 2: Find f-strings with SQL statements (assigned to variables)
        fstring_pattern = re.compile(r'(f""".*?"""|f\'\'\'.*?\'\'\'|f"[^"]*"|f\'[^\']*\')', re.DOTALL)
        for match in fstring_pattern.finditer(source_code):
            fstring = match.group(0)

            # Must be a SQL statement pattern
            if not self._is_sql_statement(fstring):
                continue

            # Must have variable interpolation
            if not re.search(r'\{[^}]+\}', fstring):
                continue

            start_pos = match.start()
            line_num = source_code[:start_pos].count('\n') + 1

            # Skip log/print statements
            line_start = source_code.rfind('\n', 0, start_pos) + 1
            line = source_code[line_start:source_code.find('\n', start_pos)]
            if self.SKIP_LINE_PATTERNS.search(line):
                continue

            if not is_near_seen(line_num):
                seen_lines.add(line_num)
                findings.append(self._create_finding(
                    file_path, line_num, ['f-string formatting'], source_lines
                ))

        return findings

    def _is_sql_statement(self, text: str) -> bool:
        """Check if text looks like a SQL statement."""
        return any(pattern.search(text) for pattern in self.SQL_STATEMENT_PATTERNS)

    def _create_finding(self, file_path: str, line_num: int, issues: List[str], source_lines: List[str]) -> Finding:
        """Create a SQL injection finding."""
        return Finding(
            id=f"SQLI_{file_path}_{line_num}",
            category="SQL Injection",
            severity=Severity.HIGH,
            confidence=0.0,
            title=f"SQL injection: {', '.join(issues)}",
            description=(
                f"SQL query on line {line_num} uses {', '.join(issues)}. "
                f"This allows attackers to modify query logic, access unauthorized data, "
                f"or execute arbitrary SQL commands."
            ),
            file_path=file_path,
            line_number=line_num,
            code_snippet=self._get_snippet_by_line(source_lines, line_num),
            recommendation=(
                "Use parameterized queries:\n"
                "1. cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))\n"
                "2. cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))\n"
                "3. Use ORM (SQLAlchemy, Django ORM)\n"
                "4. Never use f-strings or .format() in SQL"
            ),
            evidence={'injection_patterns': issues}
        )

    def _find_statement_end(self, code: str, start: int) -> int:
        """Find the end of a statement (matching parentheses)."""
        depth = 1
        i = start
        while i < len(code) and depth > 0:
            if code[i] == '(':
                depth += 1
            elif code[i] == ')':
                depth -= 1
            i += 1
        # Include a bit more context
        end = code.find('\n', i)
        return end if end != -1 else len(code)

    def _is_parameterized(self, statement: str) -> bool:
        """Check if query uses parameterized format."""
        for pattern in self.SAFE_PATTERNS:
            if re.search(pattern, statement):
                return True
        return False

    def _check_unsafe_patterns(self, statement: str) -> List[str]:
        """Check for unsafe SQL construction patterns."""
        issues = []

        # Must look like a SQL statement
        if not self._is_sql_statement(statement):
            return []

        # f-string in SQL (single or multi-line)
        if re.search(r'f["\']', statement) and re.search(r'\{[^}]+\}', statement):
            issues.append('f-string formatting')

        # .format() in SQL
        if '.format(' in statement:
            issues.append('.format() method')

        # String concatenation
        if re.search(r'["\'][^"\']*["\']\s*\+|\+\s*["\'][^"\']*["\']', statement):
            # Exclude simple string joins without variables
            if re.search(r'\+\s*\w+|\w+\s*\+', statement):
                issues.append('string concatenation')

        # % formatting without tuple (unsafe)
        if '%s' in statement or '%d' in statement:
            # Check if it's NOT followed by , (tuple)
            if not re.search(r'%[sd].*,\s*[\(\[]', statement):
                if re.search(r'%\s*\w+', statement):
                    issues.append('% formatting')

        return issues

    def _get_snippet_by_line(self, lines: List[str], line_num: int, ctx: int = 2) -> str:
        """Get code snippet around line number."""
        start = max(0, line_num - ctx - 1)
        end = min(len(lines), line_num + ctx)
        return '\n'.join(lines[start:end])

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """Calculate confidence based on evidence."""
        patterns = evidence.get('injection_patterns', [])
        if 'f-string formatting' in patterns:
            return 0.9
        if '.format() method' in patterns:
            return 0.85
        if 'string concatenation' in patterns:
            return 0.8
        return 0.75
