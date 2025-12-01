#!/usr/bin/env python3
"""
AWS Tag Scanner - Main CLI Interface

Scans AWS resources across multiple services to identify their tags and generate reports
for compliance verification.

Requires `boto3` (and `botocore`) and AWS CLI to be configured and authenticated.
This script performs read-only operations against AWS and does not modify resources.

Perfect for use in AWS CloudShell or local environments with `boto3` installed.
"""

import argparse
import sys
import logging

from aws_scanner import AWSTagScanner
from report_builder import ReportBuilder
from exporters import ResourceExporter


def main() -> None:
    parser = argparse.ArgumentParser(description='AWS Tag Scanner - No Installation Required')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--region', help='AWS region')
    parser.add_argument('--output', choices=['console', 'csv', 'json', 'xlsx', 'all'], 
                       default='console', help='Output format')
    parser.add_argument('--detailed', action='store_true', 
                       help='Show detailed resource information')
    parser.add_argument('--filename', help='Custom output filename (without extension)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Only test authentication, do not scan resources')
    parser.add_argument('--policy', help='Path to tag policy JSON file for compliance checking')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose (debug) logging')
    parser.add_argument('--quiet', action='store_true', help='Quiet mode (only warnings and errors)')
    
    args = parser.parse_args()
    
    # Configure basic logging for the CLI tool based on CLI flags
    if args.verbose:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.WARNING
    else:
        log_level = logging.INFO

    logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
    
    try:
        # Initialize scanner
        scanner = AWSTagScanner(
            profile=args.profile, 
            region=args.region, 
            dry_run=args.dry_run
        )
        
        if args.dry_run:
            return
        
        # Initialize report builder with policy
        report_builder = ReportBuilder(policy_file=args.policy)
        
        # Initialize exporter
        exporter = ResourceExporter(report_builder)
        
        # Scan resources
        resources = scanner.scan_all_resources()
        
        # Generate summary report
        summary = report_builder.generate_summary_report(resources)
        
        # Always show summary
        exporter.print_summary(summary)
        
        # Show detailed report if requested
        if args.detailed:
            exporter.print_detailed_report(resources)
        
        # Handle output options
        if args.output in ['csv', 'all']:
            exporter.export_to_csv(resources, 
                                f"{args.filename}.csv" if args.filename else None)

        if args.output in ['json', 'all']:
            exporter.export_to_json(resources, 
                                 f"{args.filename}.json" if args.filename else None)

        # If the user requested Excel output via filename extension or wants all,
        # create an .xlsx workbook with one sheet per service.
        if args.output in ['all', 'xlsx'] or (args.filename and args.filename.lower().endswith('.xlsx')):
            # prefer explicit filename without extension handling inside method
            excel_name = None
            if args.filename:
                # strip potential extension and pass base; export_to_excel will ensure .xlsx
                base = args.filename
                if base.lower().endswith('.xlsx'):
                    base = base[:-5]
                excel_name = f"{base}.xlsx"

            exporter.export_to_excel(resources, excel_name)
        
    except KeyboardInterrupt:
        print("\n[ERROR] Scan cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
