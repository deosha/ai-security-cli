"""
JSON reporter for audit results.
"""

import json
from pathlib import Path
from typing import Optional

from ..models import AuditResult


class JSONAuditReporter:
    """Generate JSON reports from audit results."""

    def generate(self, result: AuditResult) -> str:
        """
        Generate JSON string from audit result.

        Args:
            result: Audit result to convert

        Returns:
            JSON string
        """
        return json.dumps(result.to_dict(), indent=2)

    def save(self, result: AuditResult, output_path: Path) -> None:
        """
        Save audit result to JSON file.

        Args:
            result: Audit result to save
            output_path: Path to output file
        """
        output_path.write_text(self.generate(result))
