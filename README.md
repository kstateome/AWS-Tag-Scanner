# AWS Tag Scanner & Remediation Tool - Complete Guide

**Comprehensive AWS resource tagging compliance scanner and remediation tool**

Version 3.0 - Modular Architecture with Service-Specific Policies

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [What This Tool Does](#what-this-tool-does)
3. [Installation & Setup](#installation--setup)
4. [Usage Guide](#usage-guide)
5. [Modular Architecture](#modular-architecture)
6. [Service Coverage](#service-coverage)
7. [Tag Policy System](#tag-policy-system)
8. [Output Formats](#output-formats)
9. [Remediation System](#remediation-system)
10. [Security](#security)
11. [Troubleshooting](#troubleshooting)
12. [Advanced Usage](#advanced-usage)

---

## Quick Start

### Option 1: AWS CloudShell (Easiest - No Setup Required)

1. **Upload files to CloudShell:**
   - `AWS Tag Scanner/` directory (or zip file)
   - `tag_policy_service_specific.json`

2. **Activate virtual environment:**
   ```bash
   cd "AWS Tag Scanner"
   python3 -m venv .venv
   source .venv/bin/activate
   pip install boto3 openpyxl
   ```

3. **Run scanner:**
   ```bash
   python main.py --policy ../tag_policy_service_specific.json --output xlsx
   ```

4. **Generate remediation:**
   ```bash
   python main.py --policy ../tag_policy_service_specific.json --output xlsx --remediation
   ```

### Option 2: Local Machine with AWS CLI

1. **Prerequisites:**
   - Python 3.8+
   - AWS CLI configured (`aws configure`)
   - Valid AWS credentials

2. **Install dependencies:**
   ```powershell
   cd "AWS Tag Scanner"
   python -m venv .venv
   .venv\Scripts\Activate.ps1  # Windows
   # source .venv/bin/activate  # Linux/Mac
   pip install boto3 openpyxl pandas
   ```

3. **Run scanner:**
   ```powershell
   python main.py --profile your-profile --region us-east-1 --output xlsx
   ```

---

## What This Tool Does

### Core Capabilities

1. **Resource Scanning**
   - Scans 26 AWS service types across all regions
   - Identifies all tags on each resource
   - Checks compliance against service-specific policies
   - Generates detailed compliance reports

2. **Compliance Analysis**
   - Service-specific tag requirements (EC2 needs different tags than S3)
   - Core tags (required for all services)
   - Recommended tags (optional but suggested)
   - Compliance scoring per resource

3. **Remediation Planning**
   - Identifies missing tags for each resource
   - Generates smart recommendations based on existing tags
   - Provides logic explanation for each recommendation
   - Exports actionable CSV files for bulk tagging

4. **Flexible Output**
   - Console summary (quick overview)
   - CSV (Excel-compatible)
   - JSON (programmatic processing)
   - XLSX (multi-sheet workbook with charts)

### What Makes This Tool Different

- **Read-Only**: No modifications to AWS resources (safe to run in production)
- **Service-Aware**: Different requirements for EC2 vs S3 vs Lambda
- **Smart Defaults**: Recommendations based on existing tag patterns
- **Modular**: Scan only specific service categories (compute, storage, database, network, application)
- **Production-Ready**: Security hardened, input validated, error handling

---

## Installation & Setup

### System Requirements

- **Python**: 3.8 or higher
- **AWS Credentials**: Configured via AWS CLI, environment variables, or IAM role
- **Permissions**: Read-only access to AWS services (describe, list, get operations)
- **Disk Space**: ~50MB for code + output files
- **Memory**: 512MB minimum (varies by resource count)

### Step-by-Step Installation

#### 1. Clone or Download Repository

```bash
git clone https://github.com/kstateome/AWS-Tag-Scanner.git
cd AWS-Tag-Scanner
```

Or download ZIP and extract.

#### 2. Create Virtual Environment

```powershell
# Windows PowerShell
cd "AWS Tag Scanner"
python -m venv .venv
.venv\Scripts\Activate.ps1

# Linux/Mac
cd "AWS Tag Scanner"
python3 -m venv .venv
source .venv/bin/activate
```

#### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install boto3 openpyxl pandas
```

**Required packages:**
- `boto3` - AWS SDK for Python
- `openpyxl` - Excel file support
- `pandas` - Data analysis (optional, for advanced features)

#### 4. Configure AWS Credentials

**Option A: AWS CLI** (Recommended)
```bash
aws configure
# Enter: Access Key ID, Secret Access Key, Region, Output format
```

**Option B: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID="your-key-id"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

**Option C: IAM Role** (CloudShell, EC2)
- Automatic if running in CloudShell or on EC2 with IAM role attached

#### 5. Verify Installation

```bash
python main.py --dry-run
```

Should output:
```
[INFO] Successfully authenticated as: arn:aws:iam::123456789012:user/yourname
[INFO] AWS Region: us-east-1
[INFO] Dry run complete - authentication successful
```

---

## Usage Guide

### Basic Commands

#### 1. Simple Scan (Console Output)
```bash
python main.py
```

#### 2. Scan with CSV Output
```bash
python main.py --output csv
```

#### 3. Scan with Policy Compliance
```bash
python main.py --policy ../tag_policy_service_specific.json --output xlsx
```

#### 4. Scan with Remediation Plan
```bash
python main.py --policy ../tag_policy_service_specific.json --output xlsx --remediation
```

#### 5. Selective Category Scanning
```bash
# Scan only compute resources (EC2, Lambda, ECS, EKS)
python main.py --categories compute --output xlsx

# Scan multiple categories
python main.py --categories compute storage database --output csv

# Available categories: compute, storage, database, network, application
```

### Command-Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--profile` | AWS profile name | `--profile production` |
| `--region` | AWS region | `--region us-west-2` |
| `--output` | Output format | `--output xlsx` (console/csv/json/xlsx/all) |
| `--policy` | Tag policy JSON file | `--policy policy.json` |
| `--categories` | Scanner categories | `--categories compute storage` |
| `--remediation` | Generate remediation plan | `--remediation` |
| `--filename` | Custom output filename | `--filename my_scan` |
| `--detailed` | Show detailed info | `--detailed` |
| `--dry-run` | Test auth only | `--dry-run` |
| `--verbose` | Debug logging | `--verbose` |
| `--quiet` | Minimal logging | `--quiet` |

### Common Workflows

#### Workflow 1: Initial Compliance Assessment
```bash
# Step 1: Run full scan with policy
python main.py --policy ../tag_policy_service_specific.json --output xlsx --filename baseline_scan

# Step 2: Review compliance in Excel
# Open: baseline_scan.xlsx

# Step 3: Identify worst offenders
# Sort by ComplianceScore column (lowest first)

# Step 4: Generate remediation plan
python main.py --policy ../tag_policy_service_specific.json --remediation --filename baseline_scan
```

#### Workflow 2: Focused Remediation (EC2 Only)
```bash
# Scan only compute resources
python main.py --categories compute --policy ../tag_policy_service_specific.json --output xlsx --remediation

# Review: baseline_scan_remediation.csv
# Apply tags to EC2 instances

# Re-scan to verify
python main.py --categories compute --output console
```

#### Workflow 3: Monthly Compliance Reporting
```bash
# Automated scan with date-stamped files
python main.py \
  --policy ../tag_policy_service_specific.json \
  --output all \
  --filename "compliance_$(date +%Y%m%d)" \
  --remediation

# Outputs:
# - compliance_20251202.csv
# - compliance_20251202.json
# - compliance_20251202.xlsx
# - compliance_20251202_remediation.csv
```

---

## Modular Architecture

### Overview

Version 3.0 introduces a modular scanner architecture that allows selective scanning by service category.

### Directory Structure

```
AWS Tag Scanner/
├── main.py                      # CLI entry point
├── aws_scanner.py               # Main orchestrator (197 lines, down from 996!)
├── report_builder.py            # Compliance reporting
├── exporters.py                 # Output formatting
├── remediation_analyzer.py      # Remediation logic
├── security_utils.py            # Security functions
├── scanners/                    # Modular scanner modules
│   ├── __init__.py              # Package initialization
│   ├── base_scanner.py          # Base class (common functionality)
│   ├── compute_scanners.py      # EC2, Lambda, ECS, EKS
│   ├── storage_scanners.py      # S3, EBS, ECR
│   ├── database_scanners.py     # RDS, DynamoDB, ElastiCache
│   ├── network_scanners.py      # VPC, SG, ELB, CloudFront, Route53
│   └── application_scanners.py  # API GW, SNS, SQS, KMS, Secrets, CloudWatch, IAM
```

### Scanner Categories

#### 1. Compute (`compute_scanners.py`)
Scans compute and container services:
- **EC2 Instances** - Virtual machines
- **Lambda Functions** - Serverless functions
- **ECS Clusters** - Container orchestration
- **EKS Clusters** - Kubernetes clusters

**Usage:**
```bash
python main.py --categories compute
```

#### 2. Storage (`storage_scanners.py`)
Scans storage services:
- **S3 Buckets** - Object storage
- **EBS Volumes** - Block storage
- **ECR Repositories** - Container image registry

**Usage:**
```bash
python main.py --categories storage
```

#### 3. Database (`database_scanners.py`)
Scans database services:
- **RDS Instances** - Relational databases (MySQL, PostgreSQL, etc.)
- **DynamoDB Tables** - NoSQL database
- **ElastiCache Clusters** - Redis/Memcached caching

**Usage:**
```bash
python main.py --categories database
```

#### 4. Network (`network_scanners.py`)
Scans networking services:
- **VPC Resources** - VPCs, Subnets, NAT Gateways, Internet Gateways
- **Security Groups** - Firewall rules
- **Elastic IPs** - Static IP addresses
- **Load Balancers** - ALB, NLB, Classic ELB
- **CloudFront Distributions** - CDN
- **Route53 Hosted Zones** - DNS

**Usage:**
```bash
python main.py --categories network
```

#### 5. Application (`application_scanners.py`)
Scans application services:
- **API Gateways** - REST/HTTP/WebSocket APIs
- **SNS Topics** - Notification service
- **SQS Queues** - Message queuing
- **KMS Keys** - Encryption keys
- **Secrets Manager** - Secret storage
- **CloudWatch Log Groups** - Logging
- **IAM Roles** - Access management

**Usage:**
```bash
python main.py --categories application
```

### Base Scanner Class

All scanner modules inherit from `BaseScanner` which provides:

```python
class BaseScanner:
    def filter_aws_managed_tags(tags: Dict[str, str]) -> Dict[str, str]:
        """Remove AWS-managed tags (aws:*, AWS:*)"""
    
    def _create_resource_dict(...) -> Dict[str, Any]:
        """Standardize resource data structure"""
    
    def _handle_scan_error(error, service: str):
        """Centralized error handling"""
```

### Benefits of Modular Design

1. **Faster Scans** - Only scan what you need (compute-only scan is 5x faster)
2. **Easier Maintenance** - Each service category in its own file
3. **Reduced Code Duplication** - Common functionality in BaseScanner
4. **Clear Organization** - Services grouped logically
5. **Simple Extension** - Add new services to appropriate category

---

## Service Coverage

### Comprehensive Service Support (26 Services)

| Category | Services | Total Resources |
|----------|----------|-----------------|
| **Compute** | EC2, Lambda, ECS, EKS | 4 |
| **Storage** | S3, EBS, ECR | 3 |
| **Database** | RDS, DynamoDB, ElastiCache | 3 |
| **Network** | VPC, Security Groups, Elastic IPs, ALB/NLB/CLB, CloudFront, Route53 | 6 |
| **Application** | API Gateway, SNS, SQS, KMS, Secrets Manager, CloudWatch, IAM | 7 |
| **Infrastructure** | NAT Gateway, VPN, Internet Gateway | 3 |

### Service-Specific Tag Requirements

Different services need different tags:

#### EC2 Instances (Most Comprehensive)
- **Core Tags** (4): Name, department, environment, application
- **Operational Tags** (4): customer, servicescope, function, technical-contact
- **Management Tags** (4): backup, critical-list, criticality, Patch Group
- **Total Required**: 12 tags
- **Recommended**: 6 additional tags

#### S3 Buckets (Data-Focused)
- **Core Tags** (4): Name, department, environment, application
- **Data Tags** (1): data-priority
- **Total Required**: 5 tags
- **Recommended**: 6 additional tags

#### Lambda Functions (Minimal)
- **Core Tags** (4): Name, department, environment, application
- **Function Tag** (1): function
- **Total Required**: 5 tags
- **No patching/backup tags** (serverless - not applicable)

#### RDS Instances (Security-Focused)
- **Core Tags** (4): Name, department, environment, application
- **Security Tags** (3): customer, data-priority, criticality
- **Management Tags** (4): function, backup, technical-contact, rebill
- **Total Required**: 11 tags
- **No Patch Group** (AWS-managed updates)

### Tag Categories Explained

#### Core Tags (All Services)
- **Name**: Resource identifier (human-readable)
- **department**: Owning department/team
- **environment**: dev, test, staging, prod
- **application**: Application or project name

#### Operational Tags (Compute/Critical Services)
- **customer**: Primary customer/stakeholder
- **servicescope**: University-Wide, Dept-Internal, Research
- **function**: app, web, db, api, etc.
- **technical-contact**: Email for technical issues

#### Management Tags (Physical Resources)
- **backup**: Yes/No (backup policy)
- **critical-list**: Critical system identifier
- **criticality**: High, Medium, Low
- **Patch Group**: Patching schedule identifier

#### Data Tags (Storage/Database)
- **data-priority**: pii, confidential, internal, public, non-sensitive
- **data-compliance**: FERPA, HIPAA, PCI, GLBA, etc.

#### Cost Tags
- **rebill**: Y/N (charge back to department)
- **location**: Physical/logical location

#### Security Tags
- **wafv2**: WAF policy (default, exclude-all, custom)
- **os**: Operating system (for EC2)

---

## Tag Policy System

### Policy File Structure

The tag policy (`tag_policy_service_specific.json`) defines requirements per service:

```json
{
  "tag_policy": {
    "core_tags": {
      "tags": [
        {"name": "Name", "description": "Resource name"},
        {"name": "department", "description": "Owning department"},
        {"name": "environment", "description": "dev/test/prod"},
        {"name": "application", "description": "Application name"}
      ]
    },
    "service_specific_requirements": {
      "EC2": {
        "required_tags": ["customer", "servicescope", "function", ...],
        "recommended_tags": ["rebill", "data-priority", ...]
      },
      "S3": {
        "required_tags": ["customer", "data-priority"],
        "recommended_tags": ["data-compliance", ...]
      }
    }
  }
}
```

### Tag Aliases

The policy recognizes multiple variations:

| Canonical Tag | Recognized Aliases |
|---------------|-------------------|
| `environment` | env, Env, Environment, EnvType |
| `department` | dept, Dept, Department |
| `technical-contact` | technical_contact, TechnicalContact, tech-contact |
| `Patch Group` | patch_group, PatchGroup, patch-group |
| `data-priority` | data_priority, DataPriority, classification |

### Policy Compliance Checking

The scanner checks compliance for each resource:

```python
# For EC2 instance
required_tags = ["Name", "department", "environment", "application", 
                 "customer", "servicescope", "function", "technical-contact",
                 "backup", "critical-list", "criticality", "Patch Group"]

# Calculate compliance
compliance_score = (tags_present / tags_required) * 100
```

---

## Output Formats

### Console Output (Default)

```
[SCAN] Scanning AWS resources for tags...
  [Compute] Scanning compute resources...
    - EC2 Instances
    - Lambda Functions
    - ECS Clusters
    - EKS Clusters
  [Storage] Scanning storage resources...
    - S3 Buckets
    - EBS Volumes
    - ECR Repositories
[OK] Scan complete! Found 247 resources

===== AWS TAG COMPLIANCE SUMMARY =====
Total Resources: 247
Policy Compliant: 89 (36.0%)
Non-Compliant: 158 (64.0%)

Service Breakdown:
  EC2: 45/120 (37.5%)
  S3: 28/40 (70.0%)
  RDS: 12/18 (66.7%)
  ...
```

### CSV Output

**File: `aws_tags_scan_YYYYMMDD_HHMMSS.csv`**

Columns:
- Service, ResourceType, ResourceId, ResourceName, State, TagCount
- Tag_Name, Tag_department, Tag_environment, ... (one column per tag)
- PolicyCompliant, ComplianceScore, MissingRequired, MissingRecommended

**Example:**
```csv
Service,ResourceType,ResourceId,ResourceName,State,TagCount,Tag_Name,Tag_department,PolicyCompliant,ComplianceScore,MissingRequired
EC2,Instance,i-abc123,web-server-01,running,5,web-server-01,IT-Infra,NO,41.7%,customer; function; backup; Patch Group; servicescope; technical-contact; critical-list
S3,Bucket,my-bucket,my-bucket,available,4,my-bucket,Data-Services,NO,80.0%,data-priority
```

### JSON Output

**File: `aws_tags_scan_YYYYMMDD_HHMMSS.json`**

```json
{
  "resources": [
    {
      "Service": "EC2",
      "ResourceType": "Instance",
      "ResourceId": "i-abc123",
      "ResourceName": "web-server-01",
      "State": "running",
      "Tags": {
        "Name": "web-server-01",
        "department": "IT-Infra",
        "environment": "prod",
        "application": "web-app"
      },
      "TagCount": 4,
      "PolicyCompliant": false,
      "ComplianceScore": 33.3,
      "MissingRequired": ["customer", "function", "backup", ...]
    }
  ],
  "summary": {
    "total_resources": 247,
    "compliant": 89,
    "non_compliant": 158
  }
}
```

### Excel (XLSX) Output

**File: `aws_tags_scan_YYYYMMDD_HHMMSS.xlsx`**

Multi-sheet workbook:
- **Summary** - Overview with charts
- **All Resources** - Complete data
- **Non-Compliant** - Resources needing tags
- **EC2** - EC2-specific data
- **S3** - S3-specific data
- **RDS** - RDS-specific data
- ... (one sheet per service)

---

## Remediation System

### Overview

The remediation analyzer identifies missing tags and generates intelligent recommendations based on existing tag patterns.

### Remediation Output

**File: `aws_tags_scan_YYYYMMDD_HHMMSS_remediation.csv`**

**One row per missing tag** (not per resource):

```csv
Service,ResourceType,ResourceId,ResourceName,State,TagName,RecommendedValue,Logic,ExistingTagCount,MissingTagCount
EC2,Instance,i-abc123,web-server-01,running,customer,IT-Infrastructure,Copied from department tag,5,7
EC2,Instance,i-abc123,web-server-01,running,backup,Yes,Environment is 'prod' - backup recommended,5,7
EC2,Instance,i-abc123,web-server-01,running,Patch Group,prod,Copied from environment tag,5,7
S3,Bucket,my-bucket,my-bucket,available,customer,Data-Services,Copied from department tag,4,2
S3,Bucket,my-bucket,my-bucket,available,data-priority,non-sensitive,Default for non-database storage,4,2
```

### Recommendation Logic

| Missing Tag | Recommendation Logic |
|-------------|---------------------|
| **customer** | Copy from `department` tag |
| **servicescope** | `University-Wide` if prod, `Dept-Internal` otherwise |
| **function** | Infer from `ResourceName` (web, app, db, api, etc.) |
| **backup** | `Yes` if prod/critical, `No` otherwise |
| **criticality** | `High` if critical-list exists or prod database |
| **Patch Group** | Copy from `environment` tag |
| **data-priority** | `pii` for databases, `non-sensitive` otherwise |
| **technical-contact** | `REQUIRED-CONTACT@yourorg.com` (placeholder) |
| **rebill** | `N` (default: no chargeback) |
| **wafv2** | `default` for web/ELB, `exclude-all` for backend |

**Important**: Always review recommendations before applying. Values marked as `UNKNOWN`, `PLACEHOLDER`, or `REQUIRED-CONTACT` must be updated manually.

### Applying Tags

#### Method 1: AWS Console (Manual)
1. Open CSV in Excel
2. Filter by Service type
3. Copy ResourceId
4. Find resource in AWS Console
5. Add tags from CSV

#### Method 2: AWS Tag Editor (Bulk - Recommended)
1. AWS Console → Resource Groups & Tag Editor
2. Filter by resource type and IDs
3. Select multiple resources
4. "Manage tags of selected resources"
5. Add tags in bulk

#### Method 3: AWS CLI (Scripted)

```bash
# EC2 Instance
aws ec2 create-tags \
  --resources i-abc123 \
  --tags Key=customer,Value=IT-Infrastructure \
         Key=backup,Value=Yes \
         Key="Patch Group",Value=prod

# S3 Bucket
aws s3api put-bucket-tagging \
  --bucket my-bucket \
  --tagging 'TagSet=[{Key=customer,Value=IT-Infrastructure},{Key=data-priority,Value=non-sensitive}]'

# RDS Database
aws rds add-tags-to-resource \
  --resource-name arn:aws:rds:us-east-1:123456789012:db:prod-db \
  --tags Key=customer,Value=IT-Infrastructure \
         Key=backup,Value=Yes \
         Key=data-priority,Value=pii

# Lambda Function
aws lambda tag-resource \
  --resource arn:aws:lambda:us-east-1:123456789012:function:my-function \
  --tags customer=IT-Infrastructure,function=app

# Load Balancer (ALB/NLB)
aws elbv2 add-tags \
  --resource-arns arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/123 \
  --tags Key=customer,Value=IT-Infrastructure Key=function,Value=web
```

### Remediation Workflow

```
1. Generate Scan
   └─> python main.py --policy policy.json --output xlsx

2. Generate Remediation
   └─> python main.py --policy policy.json --remediation

3. Review Recommendations
   └─> Open: aws_tags_scan_*_remediation.csv
   └─> Update: UNKNOWN, PLACEHOLDER, contact emails

4. Apply Tags
   └─> Use: AWS Tag Editor (bulk) or CLI (scripted)

5. Verify Compliance
   └─> python main.py --output console
   └─> Check: Compliance score increased
```

---

## Security

### Security Features

1. **Read-Only Operations**
   - No write/modify/delete operations
   - Only describe, list, get API calls
   - Safe to run in production

2. **No Hardcoded Credentials**
   - Uses AWS SDK credential chain
   - Supports IAM roles, profiles, environment variables
   - No credentials in code or config files

3. **Input Validation**
   - File path validation (prevents directory traversal)
   - File size limits (CSV: 100MB, JSON: 10MB)
   - JSON structure validation

4. **CSV Injection Prevention**
   - Dangerous characters escaped (=, +, -, @)
   - Safe to open in Excel/LibreOffice
   - Values sanitized before export

5. **Error Handling**
   - Graceful permission denial handling
   - Continues scanning on service errors
   - Detailed error logging

### Security Best Practices

#### Before Running
- Review AWS permissions (read-only sufficient)
- Verify credentials are not hardcoded
- Test in non-production first

#### During Execution
- Monitor CloudTrail for API calls
- Verify no unexpected resource modifications
- Review scan logs for errors

#### After Scanning
- Review recommendations before applying
- Validate tag values (especially contacts, data classification)
- Test CLI commands on dev resources first

### IAM Permissions Required

Minimum read-only permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:List*",
        "s3:GetBucketTagging",
        "rds:Describe*",
        "rds:ListTagsForResource",
        "lambda:List*",
        "elasticloadbalancing:Describe*",
        "ecs:Describe*",
        "ecs:List*",
        "eks:Describe*",
        "eks:List*",
        "dynamodb:Describe*",
        "dynamodb:List*",
        "cloudfront:List*",
        "route53:List*",
        "apigateway:GET",
        "sns:List*",
        "sqs:List*",
        "kms:Describe*",
        "kms:List*",
        "secretsmanager:List*",
        "ecr:Describe*",
        "elasticache:Describe*",
        "logs:Describe*",
        "iam:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

### Security Rating

- **Overall**: 9.5/10
- **Risk Level**: Very Low
- **Production Ready**: Yes

For detailed security analysis, see: `SECURITY_ANALYSIS.md`

---

## Troubleshooting

### Common Issues

#### "No credentials found"

**Cause**: AWS credentials not configured

**Solutions**:
```bash
# Option 1: Configure AWS CLI
aws configure

# Option 2: Set environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_DEFAULT_REGION="us-east-1"

# Option 3: Use CloudShell (auto-authenticated)
# AWS Console → CloudShell icon (top right)
```

#### "Access Denied" errors

**Cause**: Insufficient IAM permissions

**Solutions**:
- Review IAM policy (see Security section)
- Add read-only permissions for denied services
- Scanner continues with services you can access

**Note**: Access Denied is normal if you lack permissions for some services. The scanner will continue scanning services you can access.

#### "0% compliance" for all resources

**Causes**:
- Wrong policy file path
- Resources have no tags
- Policy format incorrect

**Solutions**:
```bash
# Verify policy file exists
ls ../tag_policy_service_specific.json

# Test without policy
python main.py --output console

# Validate JSON
python -m json.tool < ../tag_policy_service_specific.json
```

#### Missing ResourceId in CSV

**Cause**: Using old version

**Solution**: Update to latest version (v3.0+)

#### Can't find resource in AWS Console

**Causes**:
- Wrong region
- Resource deleted
- Incorrect ResourceId

**Solutions**:
- Verify region matches scan
- Check resource still exists
- Try searching by ResourceName

#### Wrong recommended values

**Cause**: Insufficient existing tags for smart defaults

**Solution**: Review Logic column, update placeholders manually

### Performance Issues

#### Scan takes too long

**Solutions**:
```bash
# Scan only specific categories
python main.py --categories compute storage

# Scan specific region
python main.py --region us-east-1

# Skip detailed output
python main.py --output csv  # Faster than xlsx
```

#### Out of memory

**Cause**: Too many resources

**Solutions**:
- Scan by category (reduce memory usage)
- Increase system memory
- Scan regions separately

---

## Advanced Usage

### Automation & Scheduling

#### Cron Job (Linux)
```bash
# Daily scan at 2 AM
0 2 * * * cd /path/to/scanner && .venv/bin/python main.py --policy ../policy.json --output xlsx --filename "daily_$(date +\%Y\%m\%d)"
```

#### Windows Task Scheduler
```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute "C:\path\to\.venv\Scripts\python.exe" -Argument "C:\path\to\main.py --output xlsx"
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AWS Tag Scanner"
```

### CI/CD Integration

#### GitHub Actions
```yaml
name: AWS Tag Compliance
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: ${{ secrets.AWS_ROLE }}
          aws-region: us-east-1
      - name: Install dependencies
        run: |
          cd "AWS Tag Scanner"
          pip install boto3 openpyxl
      - name: Run scan
        run: |
          cd "AWS Tag Scanner"
          python main.py --policy ../policy.json --output all
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: "AWS Tag Scanner/*.xlsx"
```

### Custom Integrations

#### Python Script Integration
```python
from aws_scanner import AWSTagScanner
from report_builder import ReportBuilder
from remediation_analyzer import RemediationAnalyzer

# Initialize
scanner = AWSTagScanner(profile='prod', region='us-east-1')
report_builder = ReportBuilder(policy_file='policy.json')

# Scan resources
resources = scanner.scan_all_resources()

# Generate compliance report
summary = report_builder.generate_summary_report(resources)
print(f"Compliance: {summary['compliance_percentage']:.1f}%")

# Generate remediation
analyzer = RemediationAnalyzer(policy=report_builder.tag_policy)
analyzer.analyze_resources(resources)
analyzer.export_to_csv('remediation.csv')
```

#### Lambda Function
```python
import boto3
import json
from aws_scanner import AWSTagScanner

def lambda_handler(event, context):
    scanner = AWSTagScanner(region='us-east-1')
    resources = scanner.scan_all_resources()
    
    # Send to S3
    s3 = boto3.client('s3')
    s3.put_object(
        Bucket='compliance-reports',
        Key=f'scan_{datetime.now():%Y%m%d}.json',
        Body=json.dumps(resources)
    )
    
    return {'statusCode': 200, 'body': 'Scan complete'}
```

### Multi-Region Scanning

```bash
# Scan all regions
for region in us-east-1 us-west-2 eu-west-1; do
  python main.py --region $region --output csv --filename "scan_$region"
done

# Combine results
cat scan_*.csv > combined_scan.csv
```

### Policy Customization

Create custom policy for your organization:

```json
{
  "tag_policy": {
    "core_tags": {
      "tags": [
        {"name": "CostCenter", "description": "Billing cost center"},
        {"name": "Owner", "description": "Resource owner"},
        {"name": "Environment", "description": "Environment"},
        {"name": "Project", "description": "Project name"}
      ]
    },
    "service_specific_requirements": {
      "EC2": {
        "required_tags": ["CostCenter", "BackupPolicy"],
        "recommended_tags": ["SecurityGroup", "PatchGroup"]
      }
    }
  }
}
```

---

## FAQ

### General Questions

**Q: Will this modify my AWS resources?**
A: No. The scanner is read-only. It only performs describe/list/get operations.

**Q: What AWS permissions do I need?**
A: Read-only access to services you want to scan. See Security section for detailed IAM policy.

**Q: Does it work in CloudShell?**
A: Yes! CloudShell is the easiest way to run the scanner (no setup required).

**Q: Can I scan multiple AWS accounts?**
A: Yes, use different profiles (`--profile`) or run separately per account.

**Q: How long does a scan take?**
A: Depends on resource count. Typical: 2-5 minutes for 100-500 resources.

### Technical Questions

**Q: Why use service-specific policies?**
A: Different services need different tags. Lambda doesn't need "Patch Group", S3 doesn't need "backup" config.

**Q: Can I add new services?**
A: Yes! Add scanning methods to appropriate category scanner (e.g., `compute_scanners.py`).

**Q: How do I customize recommendation logic?**
A: Edit `remediation_analyzer.py`, method `_generate_recommendations()`.

**Q: Can I exclude certain resources?**
A: Yes, filter CSV/XLSX output, or modify scanner to skip based on tags.

**Q: Does it support AWS Organizations?**
A: Not directly. Run per account or integrate with org traversal script.

### Compliance Questions

**Q: What's a good compliance score?**
A: Target: 85%+ overall, 90%+ for critical services (databases, production).

**Q: How often should I scan?**
A: Monthly for compliance reporting, weekly during remediation, daily for monitoring.

**Q: Can I use this for audit purposes?**
A: Yes. Export reports for audit evidence. Ensure policy matches audit requirements.

**Q: What if recommended values are wrong?**
A: Review and update before applying. Recommendations are starting points, not absolutes.

---

## Success Metrics

### Measuring Progress

Track these metrics over time:

1. **Overall Compliance** - Target: 85%+
   ```
   (Compliant Resources / Total Resources) × 100
   ```

2. **Service-Specific Compliance**
   - EC2: 85%+ (operations-heavy)
   - S3: 90%+ (simpler requirements)
   - RDS: 95%+ (critical data)
   - Lambda: 80%+ (serverless)

3. **Remediation Velocity**
   - Tags added per week
   - Compliance increase per month
   - Time to 80% compliance

4. **New Resource Compliance**
   - % of new resources properly tagged
   - Target: 95%+ (catch at creation)

### Example Progress - These do not reflect any actual status

| Date | Total Resources | Compliant | Compliance % | Tags Added |
|------|-----------------|-----------|--------------|------------|
| Dec 1 | 450 | 89 | 19.8% | 0 |
| Dec 8 | 455 | 187 | 41.1% | 584 |
| Dec 15 | 460 | 312 | 67.8% | 875 |
| Dec 22 | 465 | 401 | 86.2% | 623 |
| Dec 29 | 470 | 438 | 93.2% | 289 |

**Result**: 19.8% → 93.2% compliance in 4 weeks

---

## Quick Reference

### Essential Commands

```bash
# Basic scan
python main.py

# Full scan with policy
python main.py --policy ../tag_policy_service_specific.json --output xlsx

# Scan with remediation
python main.py --policy ../policy.json --remediation --output all

# Scan specific categories
python main.py --categories compute storage --output csv

# Dry run (test authentication)
python main.py --dry-run
```

### File Outputs

| File | Description |
|------|-------------|
| `aws_tags_scan_*.csv` | Scan results (CSV) |
| `aws_tags_scan_*.json` | Scan results (JSON) |
| `aws_tags_scan_*.xlsx` | Scan results (Excel multi-sheet) |
| `*_remediation.csv` | Missing tags to add |
| `*_remediation.json` | Remediation plan (JSON) |

### AWS CLI Tag Commands

```bash
# EC2
aws ec2 create-tags --resources RESOURCE_ID --tags Key=NAME,Value=VALUE

# S3
aws s3api put-bucket-tagging --bucket BUCKET --tagging 'TagSet=[{Key=NAME,Value=VALUE}]'

# RDS
aws rds add-tags-to-resource --resource-name ARN --tags Key=NAME,Value=VALUE

# Lambda
aws lambda tag-resource --resource ARN --tags NAME=VALUE

# ELB
aws elbv2 add-tags --resource-arns ARN --tags Key=NAME,Value=VALUE
```

---

## Support & Contributing

### Getting Help

1. **Check Troubleshooting section** above
2. **Review SECURITY_ANALYSIS.md** for security questions
3. **Check GitHub Issues** for known problems
4. **Open new issue** with:
   - Command used
   - Error message
   - Python version (`python --version`)
   - Boto3 version (`pip show boto3`)

### Contributing

Contributions welcome! Areas of interest:

1. **New service scanners** (add to appropriate category)
2. **Improved recommendation logic** (remediation_analyzer.py)
3. **Performance optimizations** (parallel scanning)
4. **Documentation improvements**
5. **Bug fixes**

**Process:**
1. Fork repository
2. Create feature branch
3. Add tests if applicable
4. Submit pull request

### Repository Structure

```
AWS-Tag-Scanner/
├── README.md                        # This file
├── MODULAR_SCANNER_REFACTOR.md      # Architecture docs
├── SECURITY_ANALYSIS.md             # Security details
├── REMEDIATION_README.md            # Remediation guide
├── POLICY_UPDATE_V2.md              # Policy docs
├── tag_policy_service_specific.json # Tag policy
├── AWS Tag Scanner/                 # Main application
│   ├── main.py                      # CLI entry point
│   ├── aws_scanner.py               # Scanner orchestrator
│   ├── report_builder.py            # Compliance reports
│   ├── exporters.py                 # Output formatting
│   ├── remediation_analyzer.py      # Remediation logic
│   ├── security_utils.py            # Security functions
│   └── scanners/                    # Modular scanners
│       ├── __init__.py
│       ├── base_scanner.py
│       ├── compute_scanners.py
│       ├── storage_scanners.py
│       ├── database_scanners.py
│       ├── network_scanners.py
│       └── application_scanners.py
└── tests/                          # Test files
```

---

## Version History

### Version 3.0 (Current) - December 2025
- Modular architecture (5 category-based scanners)
- Selective category scanning
- Reduced main scanner from 996 to 197 lines
- Enhanced CLI with `--categories` argument
- 26 AWS services supported

### Version 2.0 - November 2025
- Service-specific tag policies
- Comprehensive remediation analyzer
- 26 service types (added 20 new services)
- Enhanced security features
- Excel multi-sheet output

### Version 1.0 - October 2025
- Initial release
- Basic scanning (6 services)
- CSV/JSON output
- Simple policy compliance

---

## Acknowledgments

- Built with [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) (AWS SDK for Python)
- Excel support via [openpyxl](https://openpyxl.readthedocs.io/)
- Data analysis with [pandas](https://pandas.pydata.org/)

---

## License

See LICENSE file for details.

---

## Contact

**Repository**: https://github.com/kstateome/AWS-Tag-Scanner
**Issues**: https://github.com/kstateome/AWS-Tag-Scanner/issues

---

**You're now ready to achieve AWS tagging compliance!**

**Quick Start Recap:**
1. Install dependencies: `pip install boto3 openpyxl`
2. Run scan: `python main.py --policy ../policy.json --output xlsx`
3. Generate remediation: `python main.py --policy ../policy.json --remediation`
4. Apply tags using AWS Tag Editor or CLI
5. Re-scan to verify: `python main.py --output console`

**Expected result: 0% → 85%+ compliance achievable in 2-4 weeks!**
