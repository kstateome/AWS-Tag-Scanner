"""
Base Scanner Class

Provides common functionality for all AWS resource scanners.
"""

from typing import Dict, Any, List
from botocore.exceptions import ClientError
import logging


def filter_aws_managed_tags(tags: Dict[str, str]) -> Dict[str, str]:
    """Filter out AWS-managed tags from tag dictionary"""
    return {k: v for k, v in tags.items() if not k.startswith('aws:')}


class BaseScanner:
    """Base class for all AWS resource scanners"""
    
    def __init__(self, session, region: str, logger: logging.Logger):
        """
        Initialize the base scanner
        
        Args:
            session: boto3 session object
            region: AWS region to scan
            logger: Logger instance for output
        """
        self.session = session
        self.region = region
        self.logger = logger
    
    def _handle_scan_error(self, service_name: str, error: ClientError) -> None:
        """
        Handle errors during scanning with appropriate logging
        
        Args:
            service_name: Name of the service being scanned
            error: The ClientError exception
        """
        error_code = error.response.get('Error', {}).get('Code', 'Unknown')
        
        if error_code in ['AccessDenied', 'UnauthorizedOperation', 'AccessDeniedException']:
            self.logger.debug(f"    [SKIP] No permissions to scan {service_name}")
        else:
            self.logger.warning(f"[WARN] Error scanning {service_name}: {error}")
    
    def _create_resource_dict(
        self,
        service: str,
        resource_type: str,
        resource_id: str,
        resource_name: str,
        state: str,
        tags: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Create a standardized resource dictionary
        
        Args:
            service: AWS service name
            resource_type: Type of resource
            resource_id: Unique identifier for the resource
            resource_name: Human-readable name
            state: Current state of the resource
            tags: Dictionary of resource tags
        
        Returns:
            Standardized resource dictionary
        """
        return {
            'Service': service,
            'ResourceType': resource_type,
            'ResourceId': resource_id,
            'ResourceName': resource_name,
            'State': state,
            'Tags': tags,
            'TagCount': len(tags)
        }
