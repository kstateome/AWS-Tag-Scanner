"""
AWS resource scanner for tag inventory.

This module handles:
- AWS authentication and client initialization
- Resource scanning across multiple AWS services using modular scanners
- Read-only operations for tag discovery
"""

import boto3
import sys
import logging
from typing import List, Dict, Any, Optional, Set
from botocore.exceptions import NoCredentialsError

# Import modular scanners
from scanners import (
    ComputeScanner,
    StorageScanner,
    DatabaseScanner,
    NetworkScanner,
    ApplicationScanner
)


class AWSTagScanner:
    """Scans AWS resources across multiple services to identify their tags."""
    
    # Available scanner categories
    SCANNER_CATEGORIES = {
        'compute': 'EC2, Lambda, ECS, EKS',
        'storage': 'S3, EBS, ECR',
        'database': 'RDS, DynamoDB, ElastiCache',
        'network': 'VPC, Security Groups, ELB, CloudFront, Route53',
        'application': 'API Gateway, SNS, SQS, KMS, Secrets Manager, CloudWatch, IAM'
    }
    
    def __init__(
        self, 
        profile: Optional[str] = None, 
        region: Optional[str] = None, 
        dry_run: bool = False,
        scanner_categories: Optional[List[str]] = None
    ):
        """
        Initialize AWS scanner with optional category selection.
        
        Args:
            profile: AWS profile name
            region: AWS region
            dry_run: If True, only test authentication without scanning
            scanner_categories: List of scanner categories to enable. 
                              Available: 'compute', 'storage', 'database', 'network', 'application'
                              If None, all categories are enabled.
        """
        self.dry_run = dry_run
        self.region: str = ""
        self.logger = logging.getLogger(__name__)
        
        # Determine which scanners to enable
        if scanner_categories is None:
            self.enabled_categories: Set[str] = set(self.SCANNER_CATEGORIES.keys())
        else:
            # Validate categories
            invalid = set(scanner_categories) - set(self.SCANNER_CATEGORIES.keys())
            if invalid:
                raise ValueError(f"Invalid scanner categories: {invalid}. Valid options: {list(self.SCANNER_CATEGORIES.keys())}")
            self.enabled_categories = set(scanner_categories)
        
        if self.dry_run:
            self.logger.info("[INFO] DRY RUN MODE: Will only check authentication, not scan resources")
        
        try:
            self.session = boto3.Session(profile_name=profile, region_name=region)
            self.region = region or self.session.region_name or "us-east-1"

            # Test authentication first
            sts = self.session.client('sts') # pyright: ignore[reportUnknownMemberType]
            identity = sts.get_caller_identity()
            # Avoid printing full ARN in logs; show account id only by default
            account = identity.get('Account', 'Unknown')
            self.logger.info(f"[OK] Authenticated into account: {account}")
            self.logger.info(f"[OK] Connected to AWS in region: {self.region}")
            
            if self.dry_run:
                self.logger.info("[OK] Authentication successful - dry run complete")
                return
            
            # Display enabled scanner categories
            if len(self.enabled_categories) < len(self.SCANNER_CATEGORIES):
                enabled_list = ', '.join(sorted(self.enabled_categories))
                self.logger.info(f"[INFO] Enabled scanner categories: {enabled_list}")
            else:
                self.logger.info("[INFO] All scanner categories enabled")
                
            # Initialize modular scanners based on enabled categories
            self.scanners: Dict[str, Any] = {}
            
            if 'compute' in self.enabled_categories:
                self.scanners['compute'] = ComputeScanner(self.session, self.region, self.logger)
            
            if 'storage' in self.enabled_categories:
                self.scanners['storage'] = StorageScanner(self.session, self.region, self.logger)
            
            if 'database' in self.enabled_categories:
                self.scanners['database'] = DatabaseScanner(self.session, self.region, self.logger)
            
            if 'network' in self.enabled_categories:
                self.scanners['network'] = NetworkScanner(self.session, self.region, self.logger)
            
            if 'application' in self.enabled_categories:
                self.scanners['application'] = ApplicationScanner(self.session, self.region, self.logger)
            
        except NoCredentialsError:
            self.logger.error("[ERROR] AWS credentials not found. Please configure AWS CLI first.")
            self.logger.error("[TIP] For SAML accounts, use AWS CloudShell for automatic authentication.")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"[ERROR] Error initializing AWS clients: {e}")
            sys.exit(1)
    
    def scan_all_resources(self) -> List[Dict[str, Any]]:
        """Scan all AWS resources using enabled scanner categories"""
        if self.dry_run:
            self.logger.info("[INFO] Dry run mode - skipping resource scan")
            return []
        
        self.logger.info("[SCAN] Scanning AWS resources for tags...")
        self.logger.info("[INFO] This script only performs READ operations - no changes will be made")
        
        all_resources: List[Dict[str, Any]] = []
        
        # Scan resources based on enabled categories
        if 'compute' in self.scanners:
            print("  [Compute] Scanning compute resources...")
            print("    - EC2 Instances")
            all_resources.extend(self.scanners['compute'].scan_ec2_instances())
            print("    - Lambda Functions")
            all_resources.extend(self.scanners['compute'].scan_lambda_functions())
            print("    - ECS Clusters")
            all_resources.extend(self.scanners['compute'].scan_ecs_clusters())
            print("    - EKS Clusters")
            all_resources.extend(self.scanners['compute'].scan_eks_clusters())
        
        if 'storage' in self.scanners:
            print("  [Storage] Scanning storage resources...")
            print("    - S3 Buckets")
            all_resources.extend(self.scanners['storage'].scan_s3_buckets())
            print("    - EBS Volumes")
            all_resources.extend(self.scanners['storage'].scan_ebs_volumes())
            print("    - ECR Repositories")
            all_resources.extend(self.scanners['storage'].scan_ecr_repositories())
        
        if 'database' in self.scanners:
            print("  [Database] Scanning database resources...")
            print("    - RDS Instances")
            all_resources.extend(self.scanners['database'].scan_rds_instances())
            print("    - DynamoDB Tables")
            all_resources.extend(self.scanners['database'].scan_dynamodb_tables())
            print("    - ElastiCache Clusters")
            all_resources.extend(self.scanners['database'].scan_elasticache_clusters())
        
        if 'network' in self.scanners:
            print("  [Network] Scanning network resources...")
            print("    - VPC Resources (VPCs, Subnets, NAT Gateways, IGWs)")
            all_resources.extend(self.scanners['network'].scan_vpc_resources())
            print("    - Security Groups")
            all_resources.extend(self.scanners['network'].scan_security_groups())
            print("    - Elastic IPs")
            all_resources.extend(self.scanners['network'].scan_elastic_ips())
            print("    - Load Balancers")
            all_resources.extend(self.scanners['network'].scan_load_balancers())
            print("    - CloudFront Distributions")
            all_resources.extend(self.scanners['network'].scan_cloudfront_distributions())
            print("    - Route53 Hosted Zones")
            all_resources.extend(self.scanners['network'].scan_route53_zones())
        
        if 'application' in self.scanners:
            print("  [Application] Scanning application resources...")
            print("    - API Gateways")
            all_resources.extend(self.scanners['application'].scan_api_gateways())
            print("    - SNS Topics")
            all_resources.extend(self.scanners['application'].scan_sns_topics())
            print("    - SQS Queues")
            all_resources.extend(self.scanners['application'].scan_sqs_queues())
            print("    - KMS Keys")
            all_resources.extend(self.scanners['application'].scan_kms_keys())
            print("    - Secrets Manager Secrets")
            all_resources.extend(self.scanners['application'].scan_secrets())
            print("    - CloudWatch Log Groups")
            all_resources.extend(self.scanners['application'].scan_cloudwatch_log_groups())
            print("    - IAM Roles")
            all_resources.extend(self.scanners['application'].scan_iam_roles())
        
        self.logger.info(f"[OK] Scan complete! Found {len(all_resources)} resources")
        return all_resources
