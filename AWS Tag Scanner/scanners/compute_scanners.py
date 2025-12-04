"""
Compute Resource Scanners

Scans compute-related AWS resources: EC2, Lambda, ECS, EKS
"""

from typing import Dict, Any, List
from botocore.exceptions import ClientError
from .base_scanner import BaseScanner, filter_aws_managed_tags


class ComputeScanner(BaseScanner):
    """Scanner for compute resources"""
    
    def __init__(self, session, region: str, logger):
        super().__init__(session, region, logger)
        self.ec2 = session.client('ec2')
        self.lambda_client = session.client('lambda')
        self.ecs = session.client('ecs')
        self.eks = session.client('eks')
    
    def scan_ec2_instances(self) -> List[Dict[str, Any]]:
        """Scan EC2 Instances"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling describe_instances (read-only)...")
            paginator = self.ec2.get_paginator('describe_instances')
            
            for page in paginator.paginate():
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        all_tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                        tags = filter_aws_managed_tags(all_tags)
                        
                        resources.append(self._create_resource_dict(
                            service='EC2',
                            resource_type='Instance',
                            resource_id=instance['InstanceId'],
                            resource_name=tags.get('Name', ''),
                            state=instance.get('State', {}).get('Name', 'unknown'),
                            tags=tags
                        ))
        except ClientError as e:
            self._handle_scan_error('EC2 Instances', e)
        
        return resources
    
    def scan_lambda_functions(self) -> List[Dict[str, Any]]:
        """Scan Lambda Functions"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling list_functions (read-only)...")
            paginator = self.lambda_client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                for func in page.get('Functions', []):
                    try:
                        tag_response = self.lambda_client.list_tags(Resource=func['FunctionArn'])
                        all_tags = tag_response.get('Tags', {})
                        tags = filter_aws_managed_tags(all_tags)
                        
                        resources.append(self._create_resource_dict(
                            service='Lambda',
                            resource_type='Function',
                            resource_id=func['FunctionName'],
                            resource_name=tags.get('Name', func['FunctionName']),
                            state=func.get('State', 'Active'),
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('Lambda Functions', e)
        
        return resources
    
    def scan_ecs_clusters(self) -> List[Dict[str, Any]]:
        """Scan ECS Clusters"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling list_clusters (read-only)...")
            cluster_arns = self.ecs.list_clusters().get('clusterArns', [])
            
            if cluster_arns:
                clusters = self.ecs.describe_clusters(clusters=cluster_arns).get('clusters', [])
                for cluster in clusters:
                    try:
                        tag_response = self.ecs.list_tags_for_resource(resourceArn=cluster['clusterArn'])
                        all_tags = {tag['key']: tag['value'] for tag in tag_response.get('tags', [])}
                        tags = filter_aws_managed_tags(all_tags)
                        
                        resources.append(self._create_resource_dict(
                            service='ECS',
                            resource_type='Cluster',
                            resource_id=cluster['clusterName'],
                            resource_name=tags.get('Name', cluster['clusterName']),
                            state=cluster.get('status', 'ACTIVE'),
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('ECS Clusters', e)
        
        return resources
    
    def scan_eks_clusters(self) -> List[Dict[str, Any]]:
        """Scan EKS Clusters"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling list_clusters (read-only)...")
            cluster_names = self.eks.list_clusters().get('clusters', [])
            
            for cluster_name in cluster_names:
                try:
                    cluster = self.eks.describe_cluster(name=cluster_name).get('cluster', {})
                    all_tags = cluster.get('tags', {})
                    tags = filter_aws_managed_tags(all_tags)
                    
                    resources.append(self._create_resource_dict(
                        service='EKS',
                        resource_type='Cluster',
                        resource_id=cluster_name,
                        resource_name=tags.get('Name', cluster_name),
                        state=cluster.get('status', 'ACTIVE'),
                        tags=tags
                    ))
                except ClientError:
                    pass
        except ClientError as e:
            self._handle_scan_error('EKS Clusters', e)
        
        return resources
    
    def scan_all(self) -> List[Dict[str, Any]]:
        """Scan all compute resources"""
        all_resources = []
        all_resources.extend(self.scan_ec2_instances())
        all_resources.extend(self.scan_lambda_functions())
        all_resources.extend(self.scan_ecs_clusters())
        all_resources.extend(self.scan_eks_clusters())
        return all_resources
