"""
Report generation for truslan.

This package contains HTML and CSV report generators.
"""

from .html import generate_html_report
from .csv import generate_csv_report

__all__ = [
    "generate_html_report",
    "generate_csv_report",
]
