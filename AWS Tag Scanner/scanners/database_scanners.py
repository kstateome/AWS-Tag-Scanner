"""
Database Resource Scanners

Scans database-related AWS resources: RDS, DynamoDB, ElastiCache
"""

from typing import Dict, Any, List
from botocore.exceptions import ClientError
from .base_scanner import BaseScanner, filter_aws_managed_tags


class DatabaseScanner(BaseScanner):
    """Scanner for database resources"""
    
    def __init__(self, session, region: str, logger):
        super().__init__(session, region, logger)
        self.rds = session.client('rds')
        self.dynamodb = session.client('dynamodb')
        self.elasticache = session.client('elasticache')
    
    def scan_rds_instances(self) -> List[Dict[str, Any]]:
        """Scan RDS Instances"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling describe_db_instances (read-only)...")
            paginator = self.rds.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                for db in page.get('DBInstances', []):
                    try:
                        tag_response = self.rds.list_tags_for_resource(ResourceName=db['DBInstanceArn'])
                        all_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagList', [])}
                        tags = filter_aws_managed_tags(all_tags)
                        
                        resources.append(self._create_resource_dict(
                            service='RDS',
                            resource_type='Instance',
                            resource_id=db['DBInstanceIdentifier'],
                            resource_name=tags.get('Name', db['DBInstanceIdentifier']),
                            state=db.get('DBInstanceStatus', 'unknown'),
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('RDS Instances', e)
        
        return resources
    
    def scan_dynamodb_tables(self) -> List[Dict[str, Any]]:
        """Scan DynamoDB Tables"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling list_tables (read-only)...")
            paginator = self.dynamodb.get_paginator('list_tables')
            for page in paginator.paginate():
                for table_name in page.get('TableNames', []):
                    try:
                        sts_client = self.session.client('sts')
                        account_id = sts_client.get_caller_identity()['Account']
                        table_arn = f"arn:aws:dynamodb:{self.region}:{account_id}:table/{table_name}"
                        tag_response = self.dynamodb.list_tags_of_resource(ResourceArn=table_arn)
                        all_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('Tags', [])}
                        tags = filter_aws_managed_tags(all_tags)
                        
                        resources.append(self._create_resource_dict(
                            service='DynamoDB',
                            resource_type='Table',
                            resource_id=table_name,
                            resource_name=table_name,
                            state='active',
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('DynamoDB Tables', e)
        
        return resources
    
    def scan_elasticache_clusters(self) -> List[Dict[str, Any]]:
        """Scan ElastiCache Clusters"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling describe_cache_clusters (read-only)...")
            paginator = self.elasticache.get_paginator('describe_cache_clusters')
            for page in paginator.paginate():
                for cluster in page.get('CacheClusters', []):
                    try:
                        tag_response = self.elasticache.list_tags_for_resource(
                            ResourceName=cluster['ARN']
                        )
                        all_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('TagList', [])}
                        tags = filter_aws_managed_tags(all_tags)
                        
                        resources.append(self._create_resource_dict(
                            service='ElastiCache',
                            resource_type='Cluster',
                            resource_id=cluster['CacheClusterId'],
                            resource_name=tags.get('Name', cluster['CacheClusterId']),
                            state=cluster.get('CacheClusterStatus', ''),
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('ElastiCache Clusters', e)
        
        return resources
    
    def scan_all(self) -> List[Dict[str, Any]]:
        """Scan all database resources"""
        all_resources = []
        all_resources.extend(self.scan_rds_instances())
        all_resources.extend(self.scan_dynamodb_tables())
        all_resources.extend(self.scan_elasticache_clusters())
        return all_resources
