"""Reexporta lo principal: from src.reporting import write_reports, build_alert"""
from .notifier import build_alert, send_email
from .report_generator import build_markdown, coverage_metrics, write_reports
