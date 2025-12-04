"""
Application Resource Scanners

Scans application-related AWS resources: API Gateway, SNS, SQS, KMS, Secrets Manager, CloudWatch, IAM
"""

from typing import Dict, Any, List
from botocore.exceptions import ClientError
from .base_scanner import BaseScanner, filter_aws_managed_tags


class ApplicationScanner(BaseScanner):
    """Scanner for application and service resources"""
    
    def __init__(self, session, region: str, logger):
        super().__init__(session, region, logger)
        self.apigateway = session.client('apigateway')
        self.apigatewayv2 = session.client('apigatewayv2')
        self.sns = session.client('sns')
        self.sqs = session.client('sqs')
        self.kms = session.client('kms')
        self.secretsmanager = session.client('secretsmanager')
        self.logs = session.client('logs')
        self.iam = session.client('iam')
    
    def scan_api_gateways(self) -> List[Dict[str, Any]]:
        """Scan API Gateway REST APIs and HTTP APIs"""
        resources: List[Dict[str, Any]] = []
        try:
            # REST APIs
            self.logger.debug("    [API] Calling get_rest_apis (read-only)...")
            paginator = self.apigateway.get_paginator('get_rest_apis')
            for page in paginator.paginate():
                for api in page.get('items', []):
                    all_tags = api.get('tags', {})
                    tags = filter_aws_managed_tags(all_tags)
                    
                    resources.append(self._create_resource_dict(
                        service='API Gateway',
                        resource_type='REST API',
                        resource_id=api['id'],
                        resource_name=tags.get('Name', api.get('name', '')),
                        state='active',
                        tags=tags
                    ))
            
            # HTTP APIs (API Gateway v2)
            self.logger.debug("    [API] Calling get_apis (read-only)...")
            http_apis = self.apigatewayv2.get_apis().get('Items', [])
            for api in http_apis:
                all_tags = api.get('Tags', {})
                tags = filter_aws_managed_tags(all_tags)
                
                resources.append(self._create_resource_dict(
                    service='API Gateway',
                    resource_type='HTTP API',
                    resource_id=api['ApiId'],
                    resource_name=tags.get('Name', api.get('Name', '')),
                    state='active',
                    tags=tags
                ))
        except ClientError as e:
            self._handle_scan_error('API Gateways', e)
        
        return resources
    
    def scan_sns_topics(self) -> List[Dict[str, Any]]:
        """Scan SNS Topics"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling list_topics (read-only)...")
            paginator = self.sns.get_paginator('list_topics')
            for page in paginator.paginate():
                for topic in page.get('Topics', []):
                    try:
                        tag_response = self.sns.list_tags_for_resource(ResourceArn=topic['TopicArn'])
                        all_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('Tags', [])}
                        tags = filter_aws_managed_tags(all_tags)
                        
                        topic_name = topic['TopicArn'].split(':')[-1]
                        resources.append(self._create_resource_dict(
                            service='SNS',
                            resource_type='Topic',
                            resource_id=topic['TopicArn'],
                            resource_name=tags.get('Name', topic_name),
                            state='active',
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('SNS Topics', e)
        
        return resources
    
    def scan_sqs_queues(self) -> List[Dict[str, Any]]:
        """Scan SQS Queues"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling list_queues (read-only)...")
            response = self.sqs.list_queues()
            for queue_url in response.get('QueueUrls', []):
                try:
                    tag_response = self.sqs.list_queue_tags(QueueUrl=queue_url)
                    all_tags = tag_response.get('Tags', {})
                    tags = filter_aws_managed_tags(all_tags)
                    
                    queue_name = queue_url.split('/')[-1]
                    resources.append(self._create_resource_dict(
                        service='SQS',
                        resource_type='Queue',
                        resource_id=queue_url,
                        resource_name=tags.get('Name', queue_name),
                        state='active',
                        tags=tags
                    ))
                except ClientError:
                    pass
        except ClientError as e:
            self._handle_scan_error('SQS Queues', e)
        
        return resources
    
    def scan_kms_keys(self) -> List[Dict[str, Any]]:
        """Scan KMS Keys"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling list_keys (read-only)...")
            paginator = self.kms.get_paginator('list_keys')
            for page in paginator.paginate():
                for key in page.get('Keys', []):
                    try:
                        # Skip AWS managed keys
                        key_metadata = self.kms.describe_key(KeyId=key['KeyId']).get('KeyMetadata', {})
                        if key_metadata.get('KeyManager') == 'AWS':
                            continue
                        
                        tag_response = self.kms.list_resource_tags(KeyId=key['KeyId'])
                        all_tags = {tag['TagKey']: tag['TagValue'] for tag in tag_response.get('Tags', [])}
                        tags = filter_aws_managed_tags(all_tags)
                        
                        resources.append(self._create_resource_dict(
                            service='KMS',
                            resource_type='Key',
                            resource_id=key['KeyId'],
                            resource_name=tags.get('Name', key_metadata.get('Description', '')),
                            state=key_metadata.get('KeyState', ''),
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('KMS Keys', e)
        
        return resources
    
    def scan_secrets(self) -> List[Dict[str, Any]]:
        """Scan Secrets Manager Secrets"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling list_secrets (read-only)...")
            paginator = self.secretsmanager.get_paginator('list_secrets')
            for page in paginator.paginate():
                for secret in page.get('SecretList', []):
                    all_tags = {tag['Key']: tag['Value'] for tag in secret.get('Tags', [])}
                    tags = filter_aws_managed_tags(all_tags)
                    
                    resources.append(self._create_resource_dict(
                        service='Secrets Manager',
                        resource_type='Secret',
                        resource_id=secret['ARN'],
                        resource_name=tags.get('Name', secret.get('Name', '')),
                        state='active',
                        tags=tags
                    ))
        except ClientError as e:
            self._handle_scan_error('Secrets Manager', e)
        
        return resources
    
    def scan_cloudwatch_log_groups(self) -> List[Dict[str, Any]]:
        """Scan CloudWatch Log Groups - DISABLED (too slow)"""
        self.logger.info("Skipping CloudWatch Log Groups (disabled for performance)")
        return []
    
    def scan_iam_roles(self) -> List[Dict[str, Any]]:
        """Scan IAM Roles"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling list_roles (read-only)...")
            paginator = self.iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page.get('Roles', []):
                    try:
                        tag_response = self.iam.list_role_tags(RoleName=role['RoleName'])
                        all_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('Tags', [])}
                        tags = filter_aws_managed_tags(all_tags)
                        
                        resources.append(self._create_resource_dict(
                            service='IAM',
                            resource_type='Role',
                            resource_id=role['RoleName'],
                            resource_name=tags.get('Name', role['RoleName']),
                            state='active',
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('IAM Roles', e)
        
        return resources
    
    def scan_all(self) -> List[Dict[str, Any]]:
        """Scan all application resources"""
        all_resources = []
        all_resources.extend(self.scan_api_gateways())
        all_resources.extend(self.scan_sns_topics())
        all_resources.extend(self.scan_sqs_queues())
        all_resources.extend(self.scan_kms_keys())
        all_resources.extend(self.scan_secrets())
        # all_resources.extend(self.scan_cloudwatch_log_groups())  # DISABLED: Too slow
        all_resources.extend(self.scan_iam_roles())
        return all_resources
