#!/usr/bin/env python3
"""
AWS Tag Remediation Script - Service-Specific Policy Support
Analyzes tag gaps and generates remediation recommendations based on service-specific requirements
"""

import csv
import json
import os
import sys
from typing import Dict, List, Set
from collections import defaultdict


# ============================================================================
# SECURITY UTILITIES
# ============================================================================

def validate_file_path(file_path: str, max_size_mb: int = 100) -> str:
    """
    Validate file path to prevent path traversal attacks
    
    Args:
        file_path: Path to validate
        max_size_mb: Maximum allowed file size in MB
        
    Returns:
        Absolute validated path
        
    Raises:
        ValueError: If path is invalid or file too large
    """
    if not file_path:
        raise ValueError("File path cannot be empty")
    
    # Convert to absolute path
    abs_path = os.path.abspath(file_path)
    
    # Check if file exists
    if not os.path.exists(abs_path):
        raise ValueError(f"File not found: {file_path}")
    
    # Check if it's a file (not directory)
    if not os.path.isfile(abs_path):
        raise ValueError(f"Path is not a file: {file_path}")
    
    # Check file size
    file_size = os.path.getsize(abs_path)
    max_bytes = max_size_mb * 1024 * 1024
    if file_size > max_bytes:
        raise ValueError(f"File too large: {file_size} bytes (max: {max_bytes})")
    
    return abs_path


def load_json_safely(file_path: str, max_size_mb: int = 10) -> Dict:
    """
    Load JSON file with security validations
    
    Args:
        file_path: Path to JSON file
        max_size_mb: Maximum allowed file size in MB
        
    Returns:
        Parsed JSON data
        
    Raises:
        ValueError: If file is invalid or too large
    """
    # Validate file path
    validated_path = validate_file_path(file_path, max_size_mb)
    
    # Load and parse JSON
    try:
        with open(validated_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}")
    except UnicodeDecodeError as e:
        raise ValueError(f"Invalid file encoding: {e}")
    
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object")
    
    return data


def sanitize_csv_value(value: str) -> str:
    """
    Sanitize value to prevent CSV injection attacks
    
    Prefixes dangerous characters with single quote to prevent
    formula execution in Excel/LibreOffice/Google Sheets
    
    Args:
        value: Value to sanitize
        
    Returns:
        Sanitized value safe for CSV export
    """
    if not value or not isinstance(value, str):
        return value
    
    # Characters that could trigger formula execution
    dangerous_chars = ['=', '+', '-', '@', '\t', '\r', '\n']
    
    # If value starts with dangerous character, prefix with single quote
    if value and value[0] in dangerous_chars:
        return "'" + value
    
    return value


class TagRemediator:
    """Analyzes tag gaps and generates remediation recommendations"""
    
    def __init__(self, csv_file: str, policy_file: str = None):
        self.csv_file = csv_file
        self.policy_file = policy_file
        self.policy = None
        self.resources = []
        self.tag_statistics = defaultdict(int)
        self.remediation_plan = []
        
        # Load policy if provided
        if policy_file:
            self.load_policy()
    
    def load_policy(self):
        """Load service-specific tag policy with security validations"""
        try:
            # Secure JSON loading with size validation
            policy_data = load_json_safely(self.policy_file, max_size_mb=10)
            self.policy = policy_data.get('tag_policy', {})
            
            if 'service_specific_requirements' not in self.policy:
                print("Warning: Policy doesn't contain service-specific requirements")
                self.policy = None
            else:
                print(f"[OK] Loaded policy: {self.policy.get('name', 'Unknown')}")
        except ValueError as e:
            print(f"[ERROR] Policy validation failed: {e}")
            self.policy = None
        except FileNotFoundError:
            print(f"[ERROR] Policy file not found: {self.policy_file}")
            self.policy = None
        except Exception as e:
            print(f"[ERROR] Error loading policy: {e}")
            self.policy = None
        
    def load_csv(self):
        """Load resources from CSV scan output with security validations"""
        print(f"Loading scan results from: {self.csv_file}")
        
        try:
            # Validate CSV file path (max 100MB)
            validated_path = validate_file_path(self.csv_file, max_size_mb=100)
            
            with open(validated_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.resources = list(reader)
                print(f"[OK] Loaded {len(self.resources)} resources")
        except ValueError as e:
            print(f"[ERROR] File validation failed: {e}")
            sys.exit(1)
        except FileNotFoundError:
            print(f"[ERROR] Error: File not found: {self.csv_file}")
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Error loading CSV: {e}")
            sys.exit(1)
    
    def analyze_gaps(self):
        """Analyze which tags are missing from resources using service-specific requirements"""
        print("\nAnalyzing tag gaps...")
        
        if self.policy:
            # Use service-specific requirements
            print("  Using service-specific policy requirements\n")
            service_stats = defaultdict(lambda: defaultdict(int))
            
            for resource in self.resources:
                service_type = self._get_service_type(resource)
                tags = self._extract_tags(resource)
                
                # Get requirements for this service
                required_tags = self._get_required_tags_for_service(service_type)
                
                for req_tag in required_tags:
                    if req_tag not in tags or not tags[req_tag]:
                        service_stats[service_type][req_tag] += 1
            
            # Print by service
            for service_type in sorted(service_stats.keys()):
                print(f"[{service_type.upper()}] Service:")
                print("-" * 60)
                for tag, count in sorted(service_stats[service_type].items(), key=lambda x: x[1], reverse=True):
                    service_total = sum(1 for r in self.resources if self._get_service_type(r) == service_type)
                    percentage = (count / service_total) * 100 if service_total > 0 else 0
                    print(f"  {tag:20s}: {count:4d} missing ({percentage:5.1f}%)")
                print()
            
            return service_stats
        else:
            # Fallback to hardcoded required tags
            print("  No policy loaded - using default required tags\n")
            required_tags = [
                'Name', 'customer', 'department', 'environment', 'application',
                'servicescope', 'rebill', 'function', 'data-priority',
                'technical-contact', 'wafv2', 'backup', 'critical-list',
                'criticality', 'Patch Group'
            ]
            
            missing_counts = {tag: 0 for tag in required_tags}
            
            for resource in self.resources:
                tags = self._extract_tags(resource)
                for req_tag in required_tags:
                    if req_tag not in tags or not tags[req_tag]:
                        missing_counts[req_tag] += 1
            
            print("Missing Required Tags (sorted by frequency):")
            print("-" * 60)
            for tag, count in sorted(missing_counts.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(self.resources)) * 100
                print(f"  {tag:20s}: {count:4d} missing ({percentage:5.1f}%)")
            
            return missing_counts
    
    def _get_service_type(self, resource: Dict) -> str:
        """Determine service type from resource CSV row"""
        service = resource.get('Service', '').lower()
        resource_type = resource.get('ResourceType', '').lower()
        
        if service == 'ec2':
            if 'instance' in resource_type:
                return 'ec2'
            elif 'volume' in resource_type:
                return 'ebs'
        elif service == 's3':
            return 's3'
        elif service == 'rds':
            return 'rds'
        elif service == 'lambda':
            return 'lambda'
        elif service == 'elb':
            return 'elb'
        
        return 'other'
    
    def _get_required_tags_for_service(self, service_type: str) -> List[str]:
        """Get required tags for a specific service from policy"""
        if not self.policy:
            return []
        
        # Core tags apply to all services
        core_tags = [tag['key'] for tag in self.policy.get('core_tags', {}).get('tags', [])]
        
        # Service-specific required tags
        service_reqs = self.policy.get('service_specific_requirements', {}).get(service_type, {})
        service_tags = service_reqs.get('required_tags', [])
        
        return core_tags + service_tags
    
    def _extract_tags(self, resource: Dict) -> Dict:
        """Extract tags from resource dictionary"""
        tags = {}
        for key, value in resource.items():
            # Scanner exports tags with 'Tag_' prefix
            if key.startswith('Tag_'):
                tag_name = key[4:]  # Remove 'Tag_' prefix
                tags[tag_name] = value
            # Legacy support for 'tag_' prefix (lowercase)
            elif key.startswith('tag_'):
                tag_name = key[4:]
                tags[tag_name] = value
        return tags
    
    def generate_remediation_plan(self):
        """Generate intelligent remediation recommendations"""
        print("\nGenerating remediation plan...")
        
        for resource in self.resources:
            service_type = self._get_service_type(resource)
            tags = self._extract_tags(resource)
            missing_tags = self._calculate_missing_tags(tags, service_type)
            
            if missing_tags:
                recommendations = self._generate_recommendations(resource, tags, missing_tags)
                if recommendations:
                    self.remediation_plan.append({
                        'service': service_type,
                        'resource_type': resource.get('ResourceType', resource.get('Type', 'Unknown')),
                        'resource_id': resource.get('ResourceId', resource.get('ID', 'Unknown')),
                        'resource_name': resource.get('ResourceName', tags.get('Name', 'Unnamed')),
                        'state': resource.get('State', 'Unknown'),
                        'existing_tags': len(tags),
                        'missing_count': len(missing_tags),
                        'recommendations': recommendations
                    })
        
        print(f"[OK] Generated remediation plan for {len(self.remediation_plan)} resources")
    
    def _calculate_missing_tags(self, tags: Dict, service_type: str = None) -> Set[str]:
        """Calculate which required tags are missing based on service-specific requirements"""
        # Use service-specific requirements if policy is loaded
        if self.policy and service_type:
            required = set(self._get_required_tags_for_service(service_type))
        else:
            # Fallback to all tags if no policy
            required = {
                'Name', 'customer', 'department', 'environment', 'application',
                'servicescope', 'rebill', 'function', 'data-priority',
                'technical-contact', 'wafv2', 'backup', 'critical-list',
                'criticality', 'Patch Group'
            }
        
        existing = set(k for k, v in tags.items() if v)
        return required - existing
    
    def _generate_recommendations(self, resource: Dict, tags: Dict, missing: Set[str]) -> List[Dict]:
        """Generate smart default values based on existing tags"""
        recommendations = []
        
        # Get existing tag values for reference
        environment = tags.get('environment', '').lower()
        function = tags.get('function', '').lower()
        department = tags.get('department', '')
        critical_list = tags.get('critical-list', 'N')
        
        # Generate recommendations for each missing tag
        for missing_tag in missing:
            rec = {'tag': missing_tag, 'value': None, 'logic': ''}
            
            if missing_tag == 'customer':
                rec['value'] = department if department else 'UNKNOWN'
                rec['logic'] = 'Copied from department tag'
            
            elif missing_tag == 'servicescope':
                if environment == 'prod':
                    rec['value'] = 'University-Wide'
                    rec['logic'] = 'Production resource → University-Wide'
                else:
                    rec['value'] = 'Dept-Internal'
                    rec['logic'] = 'Non-production → Dept-Internal'
            
            elif missing_tag == 'rebill':
                rec['value'] = 'N'
                rec['logic'] = 'Default: No chargeback (change if MOA exists)'
            
            elif missing_tag == 'data-priority':
                if function in ['db', 'database']:
                    rec['value'] = 'pii'
                    rec['logic'] = 'Database → PII (verify classification)'
                elif environment == 'prod':
                    rec['value'] = 'non-sensitive'
                    rec['logic'] = 'Production → non-sensitive (verify)'
                else:
                    rec['value'] = 'non-sensitive'
                    rec['logic'] = 'Default: non-sensitive'
            
            elif missing_tag == 'wafv2':
                if function == 'web':
                    rec['value'] = 'default'
                    rec['logic'] = 'Web server → default WAF rules'
                elif function in ['app', 'db', 'database']:
                    rec['value'] = 'exclude-all'
                    rec['logic'] = 'App/DB server → exclude from WAF'
                else:
                    rec['value'] = 'exclude-all'
                    rec['logic'] = 'Default: exclude-all'
            
            elif missing_tag == 'backup':
                if environment == 'prod':
                    rec['value'] = 'Yes'
                    rec['logic'] = 'Production → backup enabled'
                elif critical_list == 'Y':
                    rec['value'] = 'Yes'
                    rec['logic'] = 'Critical resource → backup enabled'
                else:
                    rec['value'] = 'No'
                    rec['logic'] = 'Non-production/non-critical → no backup'
            
            elif missing_tag == 'criticality':
                if critical_list == 'Y':
                    rec['value'] = '1 - Mission Critical'
                    rec['logic'] = 'On critical list → Mission Critical'
                elif environment == 'prod':
                    rec['value'] = '2 - Business Critical'
                    rec['logic'] = 'Production → Business Critical'
                else:
                    rec['value'] = '3 - Operational Support'
                    rec['logic'] = 'Default: Operational Support'
            
            elif missing_tag == 'Patch Group':
                if environment in ['prod', 'test', 'dev']:
                    rec['value'] = environment
                    rec['logic'] = 'Copied from environment tag'
                else:
                    rec['value'] = 'dev'
                    rec['logic'] = 'Default: dev patch group'
            
            elif missing_tag == 'technical-contact':
                rec['value'] = 'REQUIRED-CONTACT@example.com'
                rec['logic'] = 'PLACEHOLDER - Must be updated with actual contact'
            
            elif missing_tag == 'Name':
                rec['value'] = resource.get('ID', 'unnamed')
                rec['logic'] = 'Using resource ID as name'
            
            elif missing_tag == 'department':
                rec['value'] = 'UNKNOWN'
                rec['logic'] = 'PLACEHOLDER - Must be set manually'
            
            elif missing_tag == 'environment':
                rec['value'] = 'dev'
                rec['logic'] = 'DEFAULT - Verify actual environment'
            
            elif missing_tag == 'application':
                rec['value'] = 'UNKNOWN'
                rec['logic'] = 'PLACEHOLDER - Must be set manually'
            
            elif missing_tag == 'function':
                rec['value'] = 'app'
                rec['logic'] = 'DEFAULT - Verify actual function'
            
            elif missing_tag == 'critical-list':
                rec['value'] = 'N'
                rec['logic'] = 'Default: Not on critical list'
            
            if rec['value']:
                recommendations.append(rec)
        
        return recommendations
    
    def print_summary(self):
        """Print remediation summary"""
        print("\n" + "=" * 80)
        print("REMEDIATION SUMMARY")
        if self.policy:
            print("   (Using service-specific requirements)")
        print("=" * 80)
        
        # Group by service type
        by_service = defaultdict(list)
        for item in self.remediation_plan:
            service = item.get('service', 'unknown')
            by_service[service].append(item)
        
        for service_type, items in sorted(by_service.items()):
            print(f"\n[{service_type.upper()}] Service: {len(items)} resources need remediation")
            
            # Show a few examples
            for item in items[:3]:
                print(f"\n  Resource: {item['resource_name']}")
                print(f"  ID: {item['resource_id']}")
                print(f"  Type: {item['resource_type']}")
                print(f"  State: {item.get('state', 'Unknown')}")
                print(f"  Existing tags: {item['existing_tags']}, Missing: {item['missing_count']}")
                print(f"  Recommendations:")
                for rec in item['recommendations'][:5]:  # Show first 5
                    print(f"    • {rec['tag']:20s} = {rec['value']:30s}  # {rec['logic']}")
                if len(item['recommendations']) > 5:
                    more_count = len(item['recommendations']) - 5
                    print(f"    ... and {more_count} more tags")
            
            if len(items) > 3:
                remaining = len(items) - 3
                print(f"\n  ... and {remaining} more {service_type} resources")
    
    def export_to_csv(self, output_file: str):
        """Export remediation plan to CSV - ONLY shows missing tags that need to be added"""
        print(f"\nExporting remediation plan to: {output_file}")
        print("   Format: One row = One tag that needs to be added")
        print("   Shows ONLY missing tags (not existing tags)")
        
        rows = []
        for item in self.remediation_plan:
            for rec in item['recommendations']:
                rows.append({
                    'Service': sanitize_csv_value(item.get('service', 'unknown').upper()),
                    'ResourceType': sanitize_csv_value(item['resource_type']),
                    'ResourceId': sanitize_csv_value(item['resource_id']),
                    'ResourceName': sanitize_csv_value(item['resource_name']),
                    'State': sanitize_csv_value(item.get('state', 'Unknown')),
                    'TagName': sanitize_csv_value(rec['tag']),
                    'RecommendedValue': sanitize_csv_value(rec['value']),
                    'Logic': sanitize_csv_value(rec['logic']),
                    'ExistingTagCount': item['existing_tags'],
                    'MissingTagCount': item['missing_count']
                })
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            if rows:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
        
        policy_note = " (service-specific requirements)" if self.policy else ""
        print(f"\n[OK] Exported {len(rows)} missing tags across {len(self.remediation_plan)} resources{policy_note}")
        print(f"   Note: Each row = 1 tag to ADD to 1 resource")
        print(f"   Note: Use ResourceId to find the resource in AWS Console")
        print(f"   Warning: Review 'RecommendedValue' column - update placeholders before applying!")
    
    def export_to_json(self, output_file: str):
        """Export remediation plan to JSON"""
        print(f"\nExporting remediation plan to: {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.remediation_plan, f, indent=2)
        
        print(f"[OK] Exported {len(self.remediation_plan)} resource remediation plans")


def main():
    print("=" * 80)
    print("AWS Tag Remediation Analyzer")
    print("=" * 80)
    
    if len(sys.argv) < 2:
        print("\nUsage: python3 tag_remediation.py <scan_results.csv> [policy_file.json] [output_name]")
        print("\nExamples:")
        print("  python3 tag_remediation.py aws_tags_20251125_143022.csv")
        print("    → Creates: remediation_plan.csv and remediation_plan.json")
        print()
        print("  python3 tag_remediation.py aws_tags_20251125_143022.csv tag_policy_service_specific.json")
        print("    → Creates: remediation_plan.csv and remediation_plan.json")
        print()
        print("  python3 tag_remediation.py aws_tags_20251125_143022.csv tag_policy_service_specific.json ec2_fixes")
        print("    → Creates: ec2_fixes.csv and ec2_fixes.json")
        print()
        print("Note: Don't include file extensions in output name - they're added automatically!")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    policy_file = None
    output_prefix = 'remediation_plan'
    
    # Parse arguments - allow policy file and output prefix in any order
    if len(sys.argv) >= 3:
        if sys.argv[2].endswith('.json'):
            policy_file = sys.argv[2]
            if len(sys.argv) >= 4:
                output_prefix = sys.argv[3]
        else:
            output_prefix = sys.argv[2]
            if len(sys.argv) >= 4 and sys.argv[3].endswith('.json'):
                policy_file = sys.argv[3]
    
    # Remove any file extensions from output_prefix to avoid duplicates
    import os
    output_prefix = os.path.splitext(output_prefix)[0]
    
    # Create analyzer
    analyzer = TagRemediator(csv_file, policy_file)
    
    # Load and analyze
    analyzer.load_csv()
    analyzer.analyze_gaps()
    analyzer.generate_remediation_plan()
    analyzer.print_summary()
    
    # Export results
    csv_output = f"{output_prefix}.csv"
    json_output = f"{output_prefix}.json"
    
    analyzer.export_to_csv(csv_output)
    analyzer.export_to_json(json_output)
    
    print("\n" + "=" * 80)
    print("[OK] ANALYSIS COMPLETE")
    print("=" * 80)
    if policy_file:
        print("\nRecommendations are based on SERVICE-SPECIFIC requirements")
        print("   Each service (EC2, S3, RDS, Lambda, ELB, EBS) has appropriate tags")
    else:
        print("\n⚠️  Using default tag requirements (all 15 tags)")
        print("   Run with policy file for service-specific recommendations:")
        print("   python3 tag_remediation.py <csv> tag_policy_service_specific.json")
    print("\nOutput files generated:")
    print(f"   • {csv_output}")
    print(f"   • {json_output}")
    print("\nNext steps:")
    print(f"1. Review: {csv_output} (recommendations)")
    print("2. Adjust values as needed")
    print("3. Use AWS Tag Editor or scripts to apply tags")
    print("4. Re-run compliance scan to measure progress")
    print("\nTip: Start with production resources for quickest impact!")


if __name__ == '__main__':
    main()
