"""
Storage Resource Scanners

Scans storage-related AWS resources: S3, EBS, ECR
"""

from typing import Dict, Any, List
from botocore.exceptions import ClientError
from .base_scanner import BaseScanner, filter_aws_managed_tags


class StorageScanner(BaseScanner):
    """Scanner for storage resources"""
    
    def __init__(self, session, region: str, logger):
        super().__init__(session, region, logger)
        self.s3 = session.client('s3')
        self.ec2 = session.client('ec2')
        self.ecr = session.client('ecr')
    
    def scan_s3_buckets(self) -> List[Dict[str, Any]]:
        """Scan S3 Buckets"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling list_buckets (read-only)...")
            buckets = self.s3.list_buckets().get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    tag_response = self.s3.get_bucket_tagging(Bucket=bucket_name)
                    all_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagSet', [])}
                    tags = filter_aws_managed_tags(all_tags)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchTagSet':
                        tags = {}
                    else:
                        continue
                
                resources.append(self._create_resource_dict(
                    service='S3',
                    resource_type='Bucket',
                    resource_id=bucket_name,
                    resource_name=tags.get('Name', bucket_name),
                    state='available',
                    tags=tags
                ))
        except ClientError as e:
            self._handle_scan_error('S3 Buckets', e)
        
        return resources
    
    def scan_ebs_volumes(self) -> List[Dict[str, Any]]:
        """Scan EBS Volumes"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling describe_volumes (read-only)...")
            paginator = self.ec2.get_paginator('describe_volumes')
            
            for page in paginator.paginate():
                for volume in page.get('Volumes', []):
                    all_tags = {tag['Key']: tag['Value'] for tag in volume.get('Tags', [])}
                    tags = filter_aws_managed_tags(all_tags)
                    
                    resources.append(self._create_resource_dict(
                        service='EBS',
                        resource_type='Volume',
                        resource_id=volume['VolumeId'],
                        resource_name=tags.get('Name', ''),
                        state=volume.get('State', 'unknown'),
                        tags=tags
                    ))
        except ClientError as e:
            self._handle_scan_error('EBS Volumes', e)
        
        return resources
    
    def scan_ecr_repositories(self) -> List[Dict[str, Any]]:
        """Scan ECR Repositories"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling describe_repositories (read-only)...")
            paginator = self.ecr.get_paginator('describe_repositories')
            for page in paginator.paginate():
                for repo in page.get('repositories', []):
                    try:
                        tag_response = self.ecr.list_tags_for_resource(resourceArn=repo['repositoryArn'])
                        all_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('tags', [])}
                        tags = filter_aws_managed_tags(all_tags)
                        
                        resources.append(self._create_resource_dict(
                            service='ECR',
                            resource_type='Repository',
                            resource_id=repo['repositoryName'],
                            resource_name=tags.get('Name', repo['repositoryName']),
                            state='active',
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('ECR Repositories', e)
        
        return resources
    
    def scan_all(self) -> List[Dict[str, Any]]:
        """Scan all storage resources"""
        all_resources = []
        all_resources.extend(self.scan_s3_buckets())
        all_resources.extend(self.scan_ebs_volumes())
        all_resources.extend(self.scan_ecr_repositories())
        return all_resources
