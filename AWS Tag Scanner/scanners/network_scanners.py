"""
Network Resource Scanners

Scans network-related AWS resources: VPC, Security Groups, ELB, CloudFront, Route53
"""

from typing import Dict, Any, List
from botocore.exceptions import ClientError
from .base_scanner import BaseScanner, filter_aws_managed_tags


class NetworkScanner(BaseScanner):
    """Scanner for network resources"""
    
    def __init__(self, session, region: str, logger):
        super().__init__(session, region, logger)
        self.ec2 = session.client('ec2')
        self.elbv2 = session.client('elbv2')
        self.elb = session.client('elb')
        self.cloudfront = session.client('cloudfront')
        self.route53 = session.client('route53')
    
    def scan_vpc_resources(self) -> List[Dict[str, Any]]:
        """Scan VPC, Subnets, Route Tables, Internet Gateways, NAT Gateways"""
        resources: List[Dict[str, Any]] = []
        try:
            # VPCs
            self.logger.debug("    [API] Calling describe_vpcs (read-only)...")
            vpcs = self.ec2.describe_vpcs().get('Vpcs', [])
            for vpc in vpcs:
                all_tags = {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
                tags = filter_aws_managed_tags(all_tags)
                resources.append(self._create_resource_dict(
                    service='VPC',
                    resource_type='VPC',
                    resource_id=vpc['VpcId'],
                    resource_name=tags.get('Name', ''),
                    state=vpc.get('State', 'available'),
                    tags=tags
                ))
            
            # Subnets
            self.logger.debug("    [API] Calling describe_subnets (read-only)...")
            subnets = self.ec2.describe_subnets().get('Subnets', [])
            for subnet in subnets:
                all_tags = {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
                tags = filter_aws_managed_tags(all_tags)
                resources.append(self._create_resource_dict(
                    service='VPC',
                    resource_type='Subnet',
                    resource_id=subnet['SubnetId'],
                    resource_name=tags.get('Name', ''),
                    state=subnet.get('State', 'available'),
                    tags=tags
                ))
            
            # NAT Gateways
            self.logger.debug("    [API] Calling describe_nat_gateways (read-only)...")
            nat_gateways = self.ec2.describe_nat_gateways().get('NatGateways', [])
            for nat in nat_gateways:
                all_tags = {tag['Key']: tag['Value'] for tag in nat.get('Tags', [])}
                tags = filter_aws_managed_tags(all_tags)
                resources.append(self._create_resource_dict(
                    service='VPC',
                    resource_type='NAT Gateway',
                    resource_id=nat['NatGatewayId'],
                    resource_name=tags.get('Name', ''),
                    state=nat.get('State', ''),
                    tags=tags
                ))
            
            # Internet Gateways
            self.logger.debug("    [API] Calling describe_internet_gateways (read-only)...")
            igws = self.ec2.describe_internet_gateways().get('InternetGateways', [])
            for igw in igws:
                all_tags = {tag['Key']: tag['Value'] for tag in igw.get('Tags', [])}
                tags = filter_aws_managed_tags(all_tags)
                resources.append(self._create_resource_dict(
                    service='VPC',
                    resource_type='Internet Gateway',
                    resource_id=igw['InternetGatewayId'],
                    resource_name=tags.get('Name', ''),
                    state='available',
                    tags=tags
                ))
                
        except ClientError as e:
            self._handle_scan_error('VPC Resources', e)
        
        return resources
    
    def scan_security_groups(self) -> List[Dict[str, Any]]:
        """Scan Security Groups"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling describe_security_groups (read-only)...")
            paginator = self.ec2.get_paginator('describe_security_groups')
            for page in paginator.paginate():
                for sg in page.get('SecurityGroups', []):
                    all_tags = {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])}
                    tags = filter_aws_managed_tags(all_tags)
                    resources.append(self._create_resource_dict(
                        service='EC2',
                        resource_type='Security Group',
                        resource_id=sg['GroupId'],
                        resource_name=tags.get('Name', sg.get('GroupName', '')),
                        state='active',
                        tags=tags
                    ))
        except ClientError as e:
            self._handle_scan_error('Security Groups', e)
        
        return resources
    
    def scan_elastic_ips(self) -> List[Dict[str, Any]]:
        """Scan Elastic IP Addresses"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling describe_addresses (read-only)...")
            addresses = self.ec2.describe_addresses().get('Addresses', [])
            for addr in addresses:
                all_tags = {tag['Key']: tag['Value'] for tag in addr.get('Tags', [])}
                tags = filter_aws_managed_tags(all_tags)
                resources.append(self._create_resource_dict(
                    service='EC2',
                    resource_type='Elastic IP',
                    resource_id=addr.get('AllocationId', addr.get('PublicIp', '')),
                    resource_name=tags.get('Name', ''),
                    state='allocated',
                    tags=tags
                ))
        except ClientError as e:
            self._handle_scan_error('Elastic IPs', e)
        
        return resources
    
    def _scan_alb_nlb(self) -> List[Dict[str, Any]]:
        """Scan Application and Network Load Balancers"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling describe_load_balancers (ALB/NLB, read-only)...")
            paginator = self.elbv2.get_paginator('describe_load_balancers')
            
            for page in paginator.paginate():
                for lb in page.get('LoadBalancers', []):
                    try:
                        tag_response = self.elbv2.describe_tags(ResourceArns=[lb['LoadBalancerArn']])
                        all_tags = {}
                        for tag_desc in tag_response.get('TagDescriptions', []):
                            all_tags.update({tag['Key']: tag['Value'] for tag in tag_desc.get('Tags', [])})
                        tags = filter_aws_managed_tags(all_tags)
                        
                        lb_type = lb.get('Type', 'application').upper()
                        resources.append(self._create_resource_dict(
                            service='ELB',
                            resource_type=f'{lb_type} Load Balancer',
                            resource_id=lb['LoadBalancerName'],
                            resource_name=tags.get('Name', lb['LoadBalancerName']),
                            state=lb.get('State', {}).get('Code', 'unknown'),
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('ALB/NLB Load Balancers', e)
        
        return resources
    
    def _scan_classic_elb(self) -> List[Dict[str, Any]]:
        """Scan Classic Load Balancers"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling describe_load_balancers (Classic ELB, read-only)...")
            paginator = self.elb.get_paginator('describe_load_balancers')
            
            for page in paginator.paginate():
                for lb in page.get('LoadBalancerDescriptions', []):
                    try:
                        tag_response = self.elb.describe_tags(LoadBalancerNames=[lb['LoadBalancerName']])
                        all_tags = {}
                        for tag_desc in tag_response.get('TagDescriptions', []):
                            all_tags.update({tag['Key']: tag['Value'] for tag in tag_desc.get('Tags', [])})
                        tags = filter_aws_managed_tags(all_tags)
                        
                        resources.append(self._create_resource_dict(
                            service='ELB',
                            resource_type='Classic Load Balancer',
                            resource_id=lb['LoadBalancerName'],
                            resource_name=tags.get('Name', lb['LoadBalancerName']),
                            state='active',
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('Classic Load Balancers', e)
        
        return resources
    
    def scan_load_balancers(self) -> List[Dict[str, Any]]:
        """Scan all types of Load Balancers (ALB/NLB and Classic)"""
        resources: List[Dict[str, Any]] = []
        resources.extend(self._scan_alb_nlb())
        resources.extend(self._scan_classic_elb())
        return resources
    
    def scan_cloudfront_distributions(self) -> List[Dict[str, Any]]:
        """Scan CloudFront Distributions"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling list_distributions (read-only)...")
            paginator = self.cloudfront.get_paginator('list_distributions')
            for page in paginator.paginate():
                for dist in page.get('DistributionList', {}).get('Items', []):
                    try:
                        tag_response = self.cloudfront.list_tags_for_resource(Resource=dist['ARN'])
                        all_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('Tags', {}).get('Items', [])}
                        tags = filter_aws_managed_tags(all_tags)
                        
                        resources.append(self._create_resource_dict(
                            service='CloudFront',
                            resource_type='Distribution',
                            resource_id=dist['Id'],
                            resource_name=tags.get('Name', dist.get('Comment', '')),
                            state=dist.get('Status', ''),
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('CloudFront Distributions', e)
        
        return resources
    
    def scan_route53_zones(self) -> List[Dict[str, Any]]:
        """Scan Route53 Hosted Zones"""
        resources: List[Dict[str, Any]] = []
        try:
            self.logger.debug("    [API] Calling list_hosted_zones (read-only)...")
            paginator = self.route53.get_paginator('list_hosted_zones')
            for page in paginator.paginate():
                for zone in page.get('HostedZones', []):
                    try:
                        tag_response = self.route53.list_tags_for_resource(
                            ResourceType='hostedzone',
                            ResourceId=zone['Id'].split('/')[-1]
                        )
                        all_tags = {tag['Key']: tag['Value'] for tag in tag_response.get('Tags', [])}
                        tags = filter_aws_managed_tags(all_tags)
                        
                        resources.append(self._create_resource_dict(
                            service='Route53',
                            resource_type='Hosted Zone',
                            resource_id=zone['Id'],
                            resource_name=tags.get('Name', zone['Name']),
                            state='active',
                            tags=tags
                        ))
                    except ClientError:
                        pass
        except ClientError as e:
            self._handle_scan_error('Route53 Hosted Zones', e)
        
        return resources
    
    def scan_all(self) -> List[Dict[str, Any]]:
        """Scan all network resources"""
        all_resources = []
        all_resources.extend(self.scan_vpc_resources())
        all_resources.extend(self.scan_security_groups())
        all_resources.extend(self.scan_elastic_ips())
        all_resources.extend(self.scan_load_balancers())
        all_resources.extend(self.scan_cloudfront_distributions())
        all_resources.extend(self.scan_route53_zones())
        return all_resources
