"""
Report building and analysis logic for AWS tag compliance.

This module handles:
- Tag policy compliance checking
- Service-specific requirement validation
- Statistical analysis and summary generation
- Compliance scoring
"""

from typing import Dict, List, Any, Optional
from security_utils import load_json_safely
import logging


class ReportBuilder:
    """Builds compliance reports and analyzes tag data."""
    
    def __init__(self, policy_file: Optional[str] = None):
        """
        Initialize report builder with optional tag policy.
        
        Args:
            policy_file: Path to tag policy JSON file
        """
        self.tag_policy: Optional[Dict[str, Any]] = None
        self.logger = logging.getLogger(__name__)
        
        if policy_file:
            self.load_tag_policy(policy_file)
    
    def load_tag_policy(self, policy_file: str) -> None:
        """Load service-specific tag policy from JSON file with security validations"""
        try:
            # Secure JSON loading with size validation
            policy_data = load_json_safely(policy_file, max_size_mb=10)
            self.tag_policy = policy_data.get('tag_policy', {})
            
            # Validate it's a service-specific policy
            if not self.tag_policy or 'service_specific_requirements' not in self.tag_policy:
                self.logger.warning("Policy file doesn't contain service-specific requirements")
                self.logger.warning("Expected 'service_specific_requirements' section")
                self.tag_policy = None
                return
            self.logger.info(f"Loaded service-specific tag policy: {self.tag_policy.get('name', 'Unknown')}")
            services = list(self.tag_policy.get('service_specific_requirements', {}).keys())
            self.logger.info(f"Services configured: {', '.join(services)}")

            # Show core tags
            core_tags = self.tag_policy.get('core_tags', {}).get('tags', [])
            self.logger.info(f"Core tags (all services): {len(core_tags)}")
                
        except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
            # load_json_safely may raise ValueError for invalid files/paths/sizes
            self.logger.warning(f"Error loading tag policy '{policy_file}': {e}")
            self.tag_policy = None
    
    def normalize_tag_key(self, tag_key: str) -> str:
        """Normalize tag key using aliases from policy"""
        if not self.tag_policy:
            return tag_key
        
        aliases = self.tag_policy.get('tag_aliases', {})
        return aliases.get(tag_key, tag_key)
    
    def get_service_type_from_resource(self, resource: Dict[str, Any]) -> str:
        """Map resource service/type to policy service type (returns uppercase to match policy JSON)"""
        service = resource.get('Service', '')
        resource_type = resource.get('ResourceType', '')
        
        # Map AWS service names to policy service types (uppercase to match policy JSON keys)
        if service == 'EC2':
            if 'Instance' in resource_type:
                return 'EC2'
            elif 'Volume' in resource_type:
                return 'EBS'
        elif service == 'S3':
            return 'S3'
        elif service == 'RDS':
            return 'RDS'
        elif service == 'Lambda':
            return 'Lambda'
        elif service == 'ELB':
            return 'ELB'
        
        return 'other'
    
    def check_resource_compliance(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Check resource compliance using service-specific requirements"""
        if not self.tag_policy:
            return {
                'compliant': None,
                'missing_required': [],
                'missing_recommended': [],
                'unneeded_tags': [],
                'invalid_values': [],
                'compliance_score': 100.0
            }
        
        # Get service type for this resource
        service_type = self.get_service_type_from_resource(resource)
        
        # Get service-specific requirements
        service_reqs = self.tag_policy.get('service_specific_requirements', {}).get(service_type)
        core_tags = self.tag_policy.get('core_tags', {}).get('tags', [])
        
        # Build required and recommended tag lists
        required_tag_keys = [tag['key'] for tag in core_tags]
        recommended_tag_keys = []
        
        if service_reqs:
            required_tag_keys.extend(service_reqs.get('required_tags', []))
            recommended_tag_keys.extend(service_reqs.get('recommended_tags', []))
        
        # Build set of all policy-defined tags (required + recommended)
        all_policy_tags = set(required_tag_keys + recommended_tag_keys)
        
        # Get resource tags and normalize
        tags = resource.get('Tags', {})
        normalized_tags = {self.normalize_tag_key(k): v for k, v in tags.items()}
        
        missing_required = []
        missing_recommended = []
        unneeded_tags = []
        
        # Check required tags
        for tag_key in required_tag_keys:
            if tag_key not in normalized_tags or not normalized_tags[tag_key]:
                missing_required.append(tag_key)
        
        # Check recommended tags
        for tag_key in recommended_tag_keys:
            if tag_key not in normalized_tags or not normalized_tags[tag_key]:
                missing_recommended.append(tag_key)
        
        # Check for unneeded tags (tags not in policy)
        for tag_key in normalized_tags.keys():
            if tag_key not in all_policy_tags:
                unneeded_tags.append(tag_key)
        
        # Calculate compliance
        total_required = len(required_tag_keys)
        total_recommended = len(recommended_tag_keys)
        total_tags = total_required + total_recommended
        
        if total_tags > 0:
            found_required = total_required - len(missing_required)
            found_recommended = total_recommended - len(missing_recommended)
            compliance_score = ((found_required + found_recommended) / total_tags) * 100
        else:
            compliance_score = 100.0
        
        return {
            'compliant': len(missing_required) == 0,
            'missing_required': missing_required,
            'missing_recommended': missing_recommended,
            'unneeded_tags': sorted(unneeded_tags),
            'invalid_values': [],
            'compliance_score': compliance_score,
            'service_type': service_type,
            'total_required': total_required,
            'total_recommended': total_recommended
        }
    
    def _calculate_service_breakdown(self, resources: List[Dict[str, Any]], summary: Dict[str, Any]) -> tuple[int, int]:
        """Calculate per-service statistics and compliance counts"""
        compliant_count = 0
        non_compliant_count = 0
        
        for resource in resources:
            service = resource['Service']
            if service not in summary['by_service']:
                summary['by_service'][service] = {
                    'total': 0,
                    'with_tags': 0,
                    'without_tags': 0,
                    'compliant': 0,
                    'non_compliant': 0
                }
            
            summary['by_service'][service]['total'] += 1
            if resource['TagCount'] > 0:
                summary['by_service'][service]['with_tags'] += 1
            else:
                summary['by_service'][service]['without_tags'] += 1
            
            # Check compliance if policy is loaded
            if self.tag_policy:
                compliance = self.check_resource_compliance(resource)
                resource['Compliance'] = compliance
                
                if compliance['compliant']:
                    compliant_count += 1
                    summary['by_service'][service]['compliant'] += 1
                else:
                    non_compliant_count += 1
                    summary['by_service'][service]['non_compliant'] += 1
        
        return compliant_count, non_compliant_count
    
    def _calculate_compliance_summary(self, summary: Dict[str, Any], compliant_count: int, 
                                     non_compliant_count: int, total_resources: int) -> None:
        """Calculate overall compliance metrics"""
        if self.tag_policy and total_resources > 0:
            summary['compliance']['compliant'] = compliant_count
            summary['compliance']['non_compliant'] = non_compliant_count
            summary['compliance']['compliance_rate'] = (compliant_count / total_resources) * 100
    
    def _analyze_common_tags(self, resources: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze and count common tags across all resources"""
        all_tags: Dict[str, int] = {}
        for resource in resources:
            for tag_key in resource['Tags'].keys():
                all_tags[tag_key] = all_tags.get(tag_key, 0) + 1
        
        return dict(sorted(all_tags.items(), key=lambda x: x[1], reverse=True))
    
    def generate_summary_report(self, resources: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary report of tag compliance"""
        summary: Dict[str, Any] = {
            'total_resources': len(resources),
            'resources_with_tags': len([r for r in resources if r['TagCount'] > 0]),
            'resources_without_tags': len([r for r in resources if r['TagCount'] == 0]),
            'by_service': {},
            'common_tags': {},
            'compliance': {
                'compliant': 0,
                'non_compliant': 0,
                'compliance_rate': 0.0
            }
        }
        
        # Calculate service breakdown and compliance
        compliant_count, non_compliant_count = self._calculate_service_breakdown(resources, summary)
        
        # Calculate overall compliance
        self._calculate_compliance_summary(summary, compliant_count, non_compliant_count, len(resources))
        
        # Analyze common tags
        summary['common_tags'] = self._analyze_common_tags(resources)
        
        return summary
