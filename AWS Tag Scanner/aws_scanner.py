"""
AWS resource scanner for tag inventory.

This module handles:
- AWS authentication and client initialization
- Resource scanning across multiple AWS services
- Read-only operations for tag discovery
"""

import boto3
import sys
import logging
from typing import List, Dict, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError


class AWSTagScanner:
    """Scans AWS resources across multiple services to identify their tags."""
    
    def __init__(self, profile: Optional[str] = None, region: Optional[str] = None, dry_run: bool = False):
        """
        Initialize AWS clients for various services.
        
        Args:
            profile: AWS profile name
            region: AWS region
            dry_run: If True, only test authentication without scanning
        """
        self.dry_run = dry_run
        self.region: str = ""
        self.logger = logging.getLogger(__name__)
        
        if self.dry_run:
            self.logger.info("[INFO] DRY RUN MODE: Will only check authentication, not scan resources")
        
        try:
            self.session = boto3.Session(profile_name=profile, region_name=region)
            self.region = region or self.session.region_name or "us-east-1"

            # Test authentication first
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            # Avoid printing full ARN in logs; show account id only by default
            account = identity.get('Account', 'Unknown')
            self.logger.info(f"[OK] Authenticated into account: {account}")
            self.logger.info(f"[OK] Connected to AWS in region: {self.region}")
            
            if self.dry_run:
                self.logger.info("[OK] Authentication successful - dry run complete")
                return
                
            # Initialize clients for different AWS services
            self.ec2 = self.session.client('ec2')
            self.s3 = self.session.client('s3')
            self.rds = self.session.client('rds')
            self.lambda_client = self.session.client('lambda')
            self.elbv2 = self.session.client('elbv2')
            self.elb = self.session.client('elb')
            
        except NoCredentialsError:
            self.logger.error("[ERROR] AWS credentials not found. Please configure AWS CLI first.")
            self.logger.error("[TIP] For SAML accounts, use AWS CloudShell for automatic authentication.")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"[ERROR] Error initializing AWS clients: {e}")
            sys.exit(1)
    
    def scan_ec2_instances(self) -> List[Dict[str, Any]]:
        """Scan EC2 instances and their tags"""
        resources = []
        try:
            self.logger.debug("    [API] Calling describe_instances (read-only)...")
            paginator = self.ec2.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                        resources.append({
                            'Service': 'EC2',
                            'ResourceType': 'Instance',
                            'ResourceId': instance['InstanceId'],
                            'ResourceName': tags.get('Name', ''),
                            'State': instance.get('State', {}).get('Name', ''),
                            'Tags': tags,
                            'TagCount': len(tags)
                        })
        except ClientError as e:
            if e.response['Error']['Code'] == 'UnauthorizedOperation':
                self.logger.warning("[WARN] No permission to scan EC2 instances")
            else:
                self.logger.warning(f"[WARN] Error scanning EC2 instances: {e}")
        
        return resources
    
    def scan_ebs_volumes(self) -> List[Dict[str, Any]]:
        """Scan EBS volumes and their tags"""
        resources = []
        try:
            self.logger.debug("    [API] Calling describe_volumes (read-only)...")
            paginator = self.ec2.get_paginator('describe_volumes')
            for page in paginator.paginate():
                for volume in page.get('Volumes', []):
                    tags = {tag['Key']: tag['Value'] for tag in volume.get('Tags', [])}
                    resources.append({
                        'Service': 'EC2',
                        'ResourceType': 'EBS Volume',
                        'ResourceId': volume['VolumeId'],
                        'ResourceName': tags.get('Name', ''),
                        'State': volume.get('State', ''),
                        'Tags': tags,
                        'TagCount': len(tags)
                    })
        except ClientError as e:
            if e.response['Error']['Code'] == 'UnauthorizedOperation':
                self.logger.warning("[WARN] No permission to scan EBS volumes")
            else:
                self.logger.warning(f"[WARN] Error scanning EBS volumes: {e}")
        
        return resources
    
    def scan_s3_buckets(self) -> List[Dict[str, Any]]:
        """Scan S3 buckets and their tags"""
        resources = []
        try:
            self.logger.debug("    [API] Calling list_buckets (read-only)...")
            response = self.s3.list_buckets()
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                tags = {}
                try:
                    tag_response = self.s3.get_bucket_tagging(Bucket=bucket_name)
                    tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagSet', [])}
                except ClientError:
                    # Bucket has no tags or access denied
                    pass
                
                resources.append({
                    'Service': 'S3',
                    'ResourceType': 'Bucket',
                    'ResourceId': bucket_name,
                    'ResourceName': bucket_name,
                    'State': 'Active',
                    'Tags': tags,
                    'TagCount': len(tags)
                })
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                self.logger.warning("No permission to scan S3 buckets")
            else:
                self.logger.warning(f"Error scanning S3 buckets: {e}")
        
        return resources
    
    def scan_rds_instances(self) -> List[Dict[str, Any]]:
        """Scan RDS instances and their tags"""
        resources = []
        try:
            self.logger.debug("    [API] Calling describe_db_instances (read-only)...")
            paginator = self.rds.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for db in page.get('DBInstances', []):
                    tags = {}
                    try:
                        tag_response = self.rds.list_tags_for_resource(
                            ResourceName=db['DBInstanceArn']
                        )
                        tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagList', [])}
                    except ClientError:
                        pass

                    resources.append({
                        'Service': 'RDS',
                        'ResourceType': 'DB Instance',
                        'ResourceId': db['DBInstanceIdentifier'],
                        'ResourceName': db['DBInstanceIdentifier'],
                        'State': db['DBInstanceStatus'],
                        'Tags': tags,
                        'TagCount': len(tags)
                    })
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                self.logger.warning("No permission to scan RDS instances")
            else:
                self.logger.warning(f"Error scanning RDS instances: {e}")
        
        return resources
    
    def scan_lambda_functions(self) -> List[Dict[str, Any]]:
        """Scan Lambda functions and their tags"""
        resources = []
        try:
            self.logger.debug("    [API] Calling list_functions (read-only)...")
            paginator = self.lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for function in page.get('Functions', []):
                    tags = {}
                    try:
                        tag_response = self.lambda_client.list_tags(
                            Resource=function['FunctionArn']
                        )
                        tags = tag_response.get('Tags', {})
                    except ClientError:
                        pass

                    resources.append({
                        'Service': 'Lambda',
                        'ResourceType': 'Function',
                        'ResourceId': function['FunctionName'],
                        'ResourceName': function['FunctionName'],
                        'State': function.get('State', 'Active'),
                        'Tags': tags,
                        'TagCount': len(tags)
                    })
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                self.logger.warning("No permission to scan Lambda functions")
            else:
                self.logger.warning(f"Error scanning Lambda functions: {e}")
        
        return resources
    
    def _scan_alb_nlb(self) -> List[Dict[str, Any]]:
        """Scan Application and Network Load Balancers (ALB/NLB)"""
        resources = []
        try:
            self.logger.debug("    [API] Calling describe_load_balancers (ALB/NLB) (read-only)...")
            paginator = self.elbv2.get_paginator('describe_load_balancers')
            for page in paginator.paginate():
                for lb in page.get('LoadBalancers', []):
                    tags = {}
                    try:
                        tag_response = self.elbv2.describe_tags(
                            ResourceArns=[lb['LoadBalancerArn']]
                        )
                        if tag_response['TagDescriptions']:
                            tags = {tag['Key']: tag['Value'] 
                                   for tag in tag_response['TagDescriptions'][0].get('Tags', [])}
                    except ClientError:
                        pass

                    resources.append({
                        'Service': 'ELB',
                        'ResourceType': f"{lb['Type'].upper()} Load Balancer",
                        'ResourceId': lb['LoadBalancerName'],
                        'ResourceName': lb['LoadBalancerName'],
                        'State': lb['State']['Code'],
                        'Tags': tags,
                        'TagCount': len(tags)
                    })
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                self.logger.warning("No permission to scan ALB/NLB")
            else:
                self.logger.warning(f"Error scanning ALB/NLB: {e}")
        
        return resources
    
    def _scan_classic_elb(self) -> List[Dict[str, Any]]:
        """Scan Classic Load Balancers"""
        resources = []
        try:
            self.logger.debug("    [API] Calling describe_load_balancers (Classic) (read-only)...")
            paginator = self.elb.get_paginator('describe_load_balancers')
            for page in paginator.paginate():
                for lb in page.get('LoadBalancerDescriptions', []):
                    tags = {}
                    try:
                        tag_response = self.elb.describe_tags(
                            LoadBalancerNames=[lb['LoadBalancerName']]
                        )
                        if tag_response['TagDescriptions']:
                            tags = {tag['Key']: tag['Value'] 
                                   for tag in tag_response['TagDescriptions'][0].get('Tags', [])}
                    except ClientError:
                        pass

                    resources.append({
                        'Service': 'ELB',
                        'ResourceType': 'Classic Load Balancer',
                        'ResourceId': lb['LoadBalancerName'],
                        'ResourceName': lb['LoadBalancerName'],
                        'State': 'Active',
                        'Tags': tags,
                        'TagCount': len(tags)
                    })
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                self.logger.warning("No permission to scan Classic ELB")
            else:
                self.logger.warning(f"Error scanning Classic ELB: {e}")
        
        return resources
    
    def scan_load_balancers(self) -> List[Dict[str, Any]]:
        """Scan all types of Load Balancers (ALB/NLB and Classic)"""
        resources = []
        resources.extend(self._scan_alb_nlb())
        resources.extend(self._scan_classic_elb())
        return resources
    
    def scan_all_resources(self) -> List[Dict[str, Any]]:
        """Scan all supported AWS resources"""
        if self.dry_run:
            self.logger.info("[INFO] Dry run mode - skipping resource scan")
            return []
        self.logger.info("[SCAN] Scanning AWS resources for tags...")
        self.logger.info("[INFO] This script only performs READ operations - no changes will be made")
        
        all_resources = []
        
        print("  [EC2] Scanning EC2 instances...")
        all_resources.extend(self.scan_ec2_instances())
        
        print("  [EBS] Scanning EBS volumes...")
        all_resources.extend(self.scan_ebs_volumes())
        
        print("  [S3] Scanning S3 buckets...")
        all_resources.extend(self.scan_s3_buckets())
        
        print("  [RDS] Scanning RDS instances...")
        all_resources.extend(self.scan_rds_instances())
        
        print("  [Lambda] Scanning Lambda functions...")
        all_resources.extend(self.scan_lambda_functions())
        
        print("  [ELB] Scanning Load Balancers...")
        all_resources.extend(self.scan_load_balancers())
        
        self.logger.info(f"[OK] Scan complete! Found {len(all_resources)} resources")
        return all_resources
