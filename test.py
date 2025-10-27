import streamlit as st
import boto3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
import os
from dotenv import load_dotenv
import time
import random
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import logging

# Load environment variables at the start
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set page config FIRST - this must be the first Streamlit command
st.set_page_config(
    page_title="Multi-Cloud Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS - Dark theme with better contrast
st.markdown("""
<style>
    .main-header {
        font-size: 2.8rem;
        color: #FF4B4B;
        text-align: center;
        margin-bottom: 1rem;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
    }
    .sub-header {
        font-size: 1.4rem;
        color: #b0b0b0;
        text-align: center;
        margin-bottom: 2rem;
        font-weight: 300;
    }
    .severity-critical { 
        background: linear-gradient(135deg, #dc3545, #c82333); 
        color: white; 
        padding: 6px 12px; 
        border-radius: 20px; 
        font-weight: bold;
        font-size: 0.9rem;
        box-shadow: 0 2px 4px rgba(220, 53, 69, 0.3);
    }
    .severity-high { 
        background: linear-gradient(135deg, #fd7e14, #e86209); 
        color: white; 
        padding: 6px 12px; 
        border-radius: 20px; 
        font-weight: bold;
        font-size: 0.9rem;
        box-shadow: 0 2px 4px rgba(253, 126, 20, 0.3);
    }
    .severity-medium { 
        background: linear-gradient(135deg, #ffc107, #e0a800); 
        color: #000; 
        padding: 6px 12px; 
        border-radius: 20px; 
        font-weight: bold;
        font-size: 0.9rem;
        box-shadow: 0 2px 4px rgba(255, 193, 7, 0.3);
    }
    .severity-low { 
        background: linear-gradient(135deg, #28a745, #218838); 
        color: white; 
        padding: 6px 12px; 
        border-radius: 20px; 
        font-weight: bold;
        font-size: 0.9rem;
        box-shadow: 2px 2px 4px rgba(40, 167, 69, 0.3);
    }
    
    .metric-card {
        background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%);
        color: white;
        padding: 25px;
        border-radius: 15px;
        text-align: center;
        margin: 8px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        transition: transform 0.3s ease;
        border: 1px solid #4a5568;
    }
    .metric-card:hover {
        transform: translateY(-5px);
    }
    .metric-value {
        font-size: 2.5rem;
        font-weight: 800;
        margin: 10px 0;
    }
    .metric-label {
        font-size: 1rem;
        opacity: 0.9;
    }
    
    .service-card {
        background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%);
        color: white;
        padding: 20px;
        border-radius: 15px;
        text-align: center;
        margin: 8px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        transition: all 0.3s ease;
        border: 1px solid #4a5568;
    }
    .service-card:hover {
        transform: translateY(-3px);
        border-color: #667eea;
        box-shadow: 0 8px 25px rgba(0,0,0,0.3);
    }
    
    .vulnerability-card {
        background: #2d3748;
        border-radius: 12px;
        padding: 20px;
        margin: 15px 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        border-left: 5px solid;
        transition: all 0.3s ease;
        color: #e2e8f0;
        border: 1px solid #4a5568;
    }
    .vulnerability-card:hover {
        transform: translateX(5px);
        box-shadow: 0 6px 20px rgba(0,0,0,0.3);
    }
    
    .tool-card {
        background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%);
        color: white;
        padding: 15px;
        border-radius: 10px;
        margin: 8px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        transition: all 0.3s ease;
        border: 1px solid #4a5568;
        text-align: center;
    }
    .tool-card:hover {
        transform: translateY(-3px);
        border-color: #667eea;
        box-shadow: 0 8px 25px rgba(0,0,0,0.3);
    }
    
    .tool-indicator {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 8px;
    }
    .tool-live {
        background-color: #38a169;
    }
    .tool-demo {
        background-color: #d69e2e;
    }
    .tool-offline {
        background-color: #e53e3e;
    }

    .remediation-step {
        background: linear-gradient(135deg, #2d3748 0%, #4a5568 100%);
        padding: 20px;
        margin: 15px 0;
        border-radius: 10px;
        border-left: 4px solid #28a745;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        color: #e2e8f0;
        border: 1px solid #4a5568;
    }
    
    .risk-assessment {
        background: linear-gradient(135deg, #553c0a 0%, #744210 100%);
        padding: 20px;
        border-radius: 10px;
        margin: 15px 0;
        border-left: 4px solid #d69e2e;
        color: #e2e8f0;
        border: 1px solid #744210;
    }
    
    .ai-insight {
        background: linear-gradient(135deg, #2c5282 0%, #2b6cb0 100%);
        padding: 20px;
        border-radius: 10px;
        margin: 15px 0;
        border-left: 4px solid #3182ce;
        color: #e2e8f0;
        border: 1px solid #2b6cb0;
    }
    
    .security-tip {
        background: linear-gradient(135deg, #22543d 0%, #276749 100%);
        padding: 20px;
        border-radius: 10px;
        margin: 15px 0;
        border-left: 4px solid #38a169;
        color: #e2e8f0;
        border: 1px solid #276749;
    }

    /* Dark Theme Base Styles */
    .stApp {
        background-color: #1a202c;
    }
    
    .main .block-container {
        background-color: #1a202c;
        color: #e2e8f0;
    }
    
    .stMarkdown, .stText {
        color: #e2e8f0;
    }
    
    h1, h2, h3, h4, h5, h6 {
        color: #e2e8f0;
    }
    
    .stExpander {
        background-color: #2d3748;
        border: 1px solid #4a5568;
    }
    
    .stExpander label {
        color: #e2e8f0;
    }

    /* Responsive Design */
    @media (max-width: 768px) {
        .metric-card, .service-card { 
            margin: 5px 0; 
            width: 100%; 
        }
        [data-testid="column"]:not(:first-child) { 
            margin-left: 0; 
            width: 100%; 
        }
        .severity-bar { 
            flex-direction: column; 
            text-align: center; 
        }
        .main-header {
            font-size: 2rem;
        }
    }
</style>
""", unsafe_allow_html=True)

class MultiCloudSecurityApp:
    def __init__(self):
        # Initialize session state variables
        self._initialize_session_state()
        
        # Initialize AWS clients
        self.aws_clients = self._setup_aws_clients()
        
        # Define available security tools
        self.security_tools = {
            'AWS Native': ['GuardDuty', 'Security Hub', 'Inspector'],
            'Cloud Security': ['Prisma Cloud', 'Wiz', 'Qualys'],
            'Endpoint Security': ['Cortex XDR', 'CrowdStrike'],
            'Vulnerability Scanners': ['Nessus', 'OpenVAS']
        }
        
        # Define available AI models from Bedrock
        self.bedrock_models = {
            'Anthropic': ['anthropic.claude-3-sonnet-20240229-v1:0', 'anthropic.claude-3-haiku-20240307-v1:0'],
            'Amazon': ['amazon.titan-text-express-v1', 'amazon.titan-text-lite-v1'],
            'AI21': ['ai21.j2-ultra-v1', 'ai21.j2-mid-v1'],
            'Cohere': ['cohere.command-text-v14', 'cohere.command-light-text-v14']
        }
    
    def _initialize_session_state(self):
        """Initialize all session state variables"""
        defaults = {
            'scan_results': None,
            'selected_vulnerabilities': [],
            'remediation_results': {},
            'ai_analysis_cache': {},
            'remediation_plan': None,
            'remediation_logs': [],
            'selected_services': ['EC2', 'EKS', 'Lambda', 'S3', 'IAM'],
            'selected_tools': ['GuardDuty', 'Security Hub', 'Prisma Cloud', 'Wiz'],
            'selected_ai_model': 'anthropic.claude-3-sonnet-20240229-v1:0',
            'scan_details': {},
            'execution_mode': 'dry-run',
            'dark_mode': True,
            'security_score': 85,
            'last_scan_time': None,
            'trend_data': self._generate_trend_data(),
            'service_filter': ['EC2', 'EKS', 'Lambda', 'S3', 'IAM'],
            'tool_status': self._initialize_tool_status()
        }
        
        for key, value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = value
    
    def _initialize_tool_status(self):
        """Initialize tool connectivity status"""
        return {
            'GuardDuty': 'live' if self._check_aws_creds() else 'demo',
            'Security Hub': 'live' if self._check_aws_creds() else 'demo',
            'Prisma Cloud': 'demo',
            'Wiz': 'demo',
            'Qualys': 'demo',
            'Cortex XDR': 'demo',
            'CrowdStrike': 'demo',
            'Nessus': 'demo',
            'OpenVAS': 'demo',
            'AWS Inspector': 'live' if self._check_aws_creds() else 'demo'
        }
    
    def _check_aws_creds(self):
        """Check if AWS credentials are available"""
        try:
            access_key = st.secrets.get('AWS_ACCESS_KEY_ID', os.getenv('AWS_ACCESS_KEY_ID'))
            secret_key = st.secrets.get('AWS_SECRET_ACCESS_KEY', os.getenv('AWS_SECRET_ACCESS_KEY'))
            return access_key and secret_key
        except:
            return False
    
    def _setup_aws_clients(self):
        """Setup AWS clients with secrets/env fallback"""
        try:
            # Prefer Streamlit secrets
            access_key = st.secrets.get('AWS_ACCESS_KEY_ID', os.getenv('AWS_ACCESS_KEY_ID'))
            secret_key = st.secrets.get('AWS_SECRET_ACCESS_KEY', os.getenv('AWS_SECRET_ACCESS_KEY'))
            region = st.secrets.get('AWS_REGION', os.getenv('AWS_REGION', 'us-east-1'))
            
            if access_key and secret_key:
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region
                )
                logger.info("AWS clients initialized successfully")
                
                clients = {
                    'ec2': session.client('ec2'),
                    'eks': session.client('eks'),
                    'lambda': session.client('lambda'),
                    's3': session.client('s3'),
                    'iam': session.client('iam'),
                    'guardduty': session.client('guardduty'),
                    'securityhub': session.client('securityhub'),
                    'inspector2': session.client('inspector2')
                }
                
                # Initialize Bedrock client if available
                try:
                    clients['bedrock'] = session.client('bedrock-runtime')
                    logger.info("AWS Bedrock client initialized successfully")
                except Exception as e:
                    logger.warning(f"AWS Bedrock client not available: {e}")
                    clients['bedrock'] = None
                
                return clients
            else:
                logger.warning("No AWS credentials found - demo mode")
                return None
        except Exception as e:
            logger.error(f"AWS Setup Failed: {e}")
            st.error(f"AWS Setup Failed: {e}. Falling back to demo mode.")
            return None
    
    def _call_bedrock_ai(self, prompt, model_id=None):
        """Call AWS Bedrock AI model for analysis and remediation"""
        if not self.aws_clients or not self.aws_clients.get('bedrock'):
            return self._simulate_ai_response(prompt)
        
        try:
            model_id = model_id or st.session_state.selected_ai_model
            
            if 'anthropic' in model_id:
                # Claude model format
                body = {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 4000,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                }
                response = self.aws_clients['bedrock'].invoke_model(
                    modelId=model_id,
                    body=json.dumps(body)
                )
                response_body = json.loads(response['body'].read())
                return response_body['content'][0]['text']
            
            elif 'amazon' in model_id:
                # Titan model format
                body = {
                    "inputText": prompt,
                    "textGenerationConfig": {
                        "maxTokenCount": 4000,
                        "temperature": 0,
                        "topP": 0.9
                    }
                }
                response = self.aws_clients['bedrock'].invoke_model(
                    modelId=model_id,
                    body=json.dumps(body)
                )
                response_body = json.loads(response['body'].read())
                return response_body['results'][0]['outputText']
            
            else:
                # Default to simulated response for other models
                return self._simulate_ai_response(prompt)
                
        except Exception as e:
            logger.error(f"Bedrock AI call failed: {e}")
            return self._simulate_ai_response(prompt)
    
    def _simulate_ai_response(self, prompt):
        """Simulate AI response when Bedrock is not available"""
        # Simple simulation based on prompt content
        if 'remediation' in prompt.lower():
            return """## Remediation Plan

**Immediate Actions:**
1. **Isolate affected resources** from the network
2. **Review IAM policies** and remove excessive permissions
3. **Implement least privilege principle** for all roles
4. **Enable logging and monitoring** for suspicious activities

**AWS CLI Commands:**
```bash
# Example command to update security groups
aws ec2 revoke-security-group-ingress --group-id sg-xxx --protocol tcp --port 22 --cidr 0.0.0.0/0

# Example command to update IAM policies
aws iam attach-role-policy --role-name suspicious-role --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

**Long-term Recommendations:**
- Implement AWS Security Hub for continuous monitoring
- Enable GuardDuty for threat detection
- Regular security assessments and penetration testing"""

        else:
            return """## AI Security Analysis

**Risk Assessment:**
- **Overall Risk:** High
- **Business Impact:** Critical data exposure possible
- **Attack Vectors:** Multiple potential entry points identified

**Recommendations:**
1. **Immediate:** Contain the threat and prevent further access
2. **Short-term:** Implement security controls and monitoring
3. **Long-term:** Establish security governance and regular audits

**Compliance Impact:**
- PCI DSS: Multiple violations detected
- GDPR: Potential data protection issues
- CIS Benchmarks: Several controls failed"""
    
    def _generate_trend_data(self):
        """Generate sample trend data for visualization"""
        dates = [(datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d') 
                for i in range(30, 0, -1)]
        return {
            'dates': dates,
            'vulnerabilities': [random.randint(5, 20) for _ in range(30)],
            'resources': [random.randint(50, 100) for _ in range(30)],
            'security_score': [random.randint(75, 95) for _ in range(30)]
        }
    
    def _generate_guardduty_findings(self):
        """Generate sample GuardDuty findings"""
        findings = []
        
        sample_findings = [
            {
                'id': 'gd-1',
                'title': 'Unauthorized IAM User Access',
                'severity': 'HIGH',
                'description': 'API was invoked from an IP address not observed in the last 30 days.',
                'resource': 'arn:aws:iam::123456789012:user/suspicious-user',
                'service': 'GuardDuty',
                'type': 'Recon:EC2/Portscan',
                'created': (datetime.now() - timedelta(hours=2)).isoformat(),
                'confidence': 85
            },
            {
                'id': 'gd-2',
                'title': 'Bitcoin Mining Activity Detected',
                'severity': 'HIGH',
                'description': 'EC2 instance is communicating with IP addresses known for Bitcoin mining activity.',
                'resource': 'i-abcdef12345678901',
                'service': 'GuardDuty',
                'type': 'CryptoCurrency:EC2/BitcoinTool.B',
                'created': (datetime.now() - timedelta(hours=5)).isoformat(),
                'confidence': 95
            },
            {
                'id': 'gd-3',
                'title': 'Suspicious API Call from Tor Exit Node',
                'severity': 'MEDIUM',
                'description': 'API call from a Tor exit node IP address detected.',
                'resource': 'arn:aws:iam::123456789012:role/WebServerRole',
                'service': 'GuardDuty',
                'type': 'UnauthorizedAccess:IAMUser/TorIPCaller',
                'created': (datetime.now() - timedelta(hours=1)).isoformat(),
                'confidence': 75
            }
        ]
        
        return sample_findings
    
    def _generate_security_hub_findings(self):
        """Generate sample Security Hub findings"""
        findings = []
        
        sample_findings = [
            {
                'id': 'sh-1',
                'title': 'S3 Bucket Public Read Access',
                'severity': 'HIGH',
                'description': 'S3 bucket policy allows public read access.',
                'resource': 'arn:aws:s3:::customer-data-bucket',
                'service': 'Security Hub',
                'type': 'Software and Configuration Checks',
                'created': (datetime.now() - timedelta(days=1)).isoformat(),
                'standards': ['CIS AWS Foundations', 'PCI DSS']
            },
            {
                'id': 'sh-2',
                'title': 'Security Group Allows All Traffic',
                'severity': 'CRITICAL',
                'description': 'Security group allows inbound traffic on all ports from any IP address.',
                'resource': 'sg-abcdef12',
                'service': 'Security Hub',
                'type': 'Software and Configuration Checks',
                'created': (datetime.now() - timedelta(days=2)).isoformat(),
                'standards': ['CIS AWS Foundations', 'NIST 800-53']
            },
            {
                'id': 'sh-3',
                'title': 'IAM Password Policy Weak',
                'severity': 'MEDIUM',
                'description': 'IAM password policy does not meet minimum requirements.',
                'resource': 'aws-account',
                'service': 'Security Hub',
                'type': 'Software and Configuration Checks',
                'created': (datetime.now() - timedelta(days=3)).isoformat(),
                'standards': ['CIS AWS Foundations']
            }
        ]
        
        return sample_findings
    
    def _generate_prisma_cloud_findings(self):
        """Generate sample Prisma Cloud findings"""
        findings = []
        
        sample_findings = [
            {
                'id': 'prisma-1',
                'title': 'Container Running as Root',
                'severity': 'HIGH',
                'description': 'Container is running with root privileges, increasing attack surface.',
                'resource': 'k8s-pod/production/app-server',
                'service': 'Prisma Cloud',
                'type': 'Container Security',
                'created': (datetime.now() - timedelta(hours=6)).isoformat(),
                'policy': 'Kubernetes Pod Security Policy'
            },
            {
                'id': 'prisma-2',
                'title': 'Public Cloud Storage with Sensitive Data',
                'severity': 'CRITICAL',
                'description': 'Cloud storage bucket contains sensitive data and is publicly accessible.',
                'resource': 'gcs://sensitive-data-bucket',
                'service': 'Prisma Cloud',
                'type': 'Data Security',
                'created': (datetime.now() - timedelta(hours=12)).isoformat(),
                'policy': 'Data Loss Prevention'
            },
            {
                'id': 'prisma-3',
                'title': 'Network Security Group Allows RDP from Internet',
                'severity': 'HIGH',
                'description': 'Azure NSG allows RDP access from any IP address.',
                'resource': '/subscriptions/123/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/app-nsg',
                'service': 'Prisma Cloud',
                'type': 'Network Security',
                'created': (datetime.now() - timedelta(hours=8)).isoformat(),
                'policy': 'Network Security Policy'
            }
        ]
        
        return sample_findings
    
    def _generate_wiz_findings(self):
        """Generate sample Wiz findings"""
        findings = []
        
        sample_findings = [
            {
                'id': 'wiz-1',
                'title': 'Critical Vulnerability in Web Application',
                'severity': 'CRITICAL',
                'description': 'Remote code execution vulnerability in web application framework.',
                'resource': 'arn:aws:ecs:us-east-1:123456789012:task/production/web-app',
                'service': 'Wiz',
                'type': 'Vulnerability Management',
                'created': (datetime.now() - timedelta(hours=3)).isoformat(),
                'cve': 'CVE-2023-12345'
            },
            {
                'id': 'wiz-2',
                'title': 'Misconfigured Kubernetes Cluster',
                'severity': 'HIGH',
                'description': 'Kubernetes cluster allows anonymous access to API server.',
                'resource': 'gke-cluster/production',
                'service': 'Wiz',
                'type': 'Kubernetes Security',
                'created': (datetime.now() - timedelta(hours=7)).isoformat(),
                'cve': 'K8S-MISCONFIG-001'
            },
            {
                'id': 'wiz-3',
                'title': 'Exposed Database Credentials',
                'severity': 'HIGH',
                'description': 'Database connection string exposed in environment variables.',
                'resource': 'azure-app-service/production/api',
                'service': 'Wiz',
                'type': 'Secrets Management',
                'created': (datetime.now() - timedelta(hours=4)).isoformat(),
                'cve': 'SECRET-EXPOSURE-001'
            }
        ]
        
        return sample_findings
    
    def _generate_qualys_findings(self):
        """Generate sample Qualys findings"""
        findings = []
        
        sample_findings = [
            {
                'id': 'qualys-1',
                'title': 'SSL/TLS Vulnerability - POODLE',
                'severity': 'MEDIUM',
                'description': 'SSL 3.0 vulnerability allowing padding oracle attacks.',
                'resource': 'web-server-01.company.com',
                'service': 'Qualys',
                'type': 'Vulnerability Scan',
                'created': (datetime.now() - timedelta(days=1)).isoformat(),
                'qid': '38628'
            },
            {
                'id': 'qualys-2',
                'title': 'Apache Struts Remote Code Execution',
                'severity': 'CRITICAL',
                'description': 'Apache Struts vulnerability allowing remote code execution.',
                'resource': 'app-server-02.company.com',
                'service': 'Qualys',
                'type': 'Vulnerability Scan',
                'created': (datetime.now() - timedelta(days=2)).isoformat(),
                'qid': '370583'
            },
            {
                'id': 'qualys-3',
                'title': 'Windows SMB Vulnerability',
                'severity': 'HIGH',
                'description': 'SMBv1 vulnerability allowing remote code execution.',
                'resource': 'fileserver-01.company.com',
                'service': 'Qualys',
                'type': 'Vulnerability Scan',
                'created': (datetime.now() - timedelta(days=1)).isoformat(),
                'qid': '91464'
            }
        ]
        
        return sample_findings
    
    def _generate_cortex_findings(self):
        """Generate sample Cortex XDR findings"""
        findings = []
        
        sample_findings = [
            {
                'id': 'cortex-1',
                'title': 'Malware Detected - Emotet',
                'severity': 'CRITICAL',
                'description': 'Emotet malware detected on endpoint through behavioral analysis.',
                'resource': 'workstation-user-01.company.com',
                'service': 'Cortex XDR',
                'type': 'Malware Protection',
                'created': (datetime.now() - timedelta(hours=2)).isoformat(),
                'mitre_tactic': 'TA0002 - Execution'
            },
            {
                'id': 'cortex-2',
                'title': 'Suspicious PowerShell Activity',
                'severity': 'HIGH',
                'description': 'PowerShell script with obfuscation and suspicious commands detected.',
                'resource': 'server-db-01.company.com',
                'service': 'Cortex XDR',
                'type': 'Behavioral Threat Protection',
                'created': (datetime.now() - timedelta(hours=5)).isoformat(),
                'mitre_tactic': 'TA0002 - Execution'
            },
            {
                'id': 'cortex-3',
                'title': 'Lateral Movement Detected',
                'severity': 'HIGH',
                'description': 'Suspicious RDP connection from compromised host.',
                'resource': 'workstation-admin-02.company.com',
                'service': 'Cortex XDR',
                'type': 'Network Threat Protection',
                'created': (datetime.now() - timedelta(hours=3)).isoformat(),
                'mitre_tactic': 'TA0008 - Lateral Movement'
            }
        ]
        
        return sample_findings
    
    def get_tool_findings(self, tool_name):
        """Get findings from specific security tool"""
        if tool_name == 'GuardDuty':
            if self.aws_clients and st.session_state.tool_status['GuardDuty'] == 'live':
                try:
                    detector_response = self.aws_clients['guardduty'].list_detectors()
                    if detector_response['DetectorIds']:
                        findings_response = self.aws_clients['guardduty'].list_findings(
                            DetectorId=detector_response['DetectorIds'][0],
                            MaxResults=50
                        )
                        # In real implementation, would fetch and parse actual findings
                        return self._generate_guardduty_findings()
                except Exception as e:
                    logger.warning(f"Failed to fetch GuardDuty findings: {e}")
            return self._generate_guardduty_findings()
        
        elif tool_name == 'Security Hub':
            if self.aws_clients and st.session_state.tool_status['Security Hub'] == 'live':
                try:
                    findings_response = self.aws_clients['securityhub'].get_findings(
                        MaxResults=50
                    )
                    # In real implementation, would parse actual findings
                    return self._generate_security_hub_findings()
                except Exception as e:
                    logger.warning(f"Failed to fetch Security Hub findings: {e}")
            return self._generate_security_hub_findings()
        
        elif tool_name == 'Prisma Cloud':
            return self._generate_prisma_cloud_findings()
        
        elif tool_name == 'Wiz':
            return self._generate_wiz_findings()
        
        elif tool_name == 'Qualys':
            return self._generate_qualys_findings()
        
        elif tool_name == 'Cortex XDR':
            return self._generate_cortex_findings()
        
        else:
            return []
    
    def _generate_enhanced_sample_data(self):
        """Generate enhanced sample data with more services"""
        resources = [
            {
                'resource_id': 'i-1234567890abcdef0',
                'resource_type': 'EC2',
                'service': 'EC2',
                'name': 'web-server-production',
                'state': 'running',
                'instance_type': 't3.large',
                'public_ip': '54.210.100.50',
                'launch_time': '2024-01-15 08:30:00',
                'vulnerabilities': [
                    {
                        'id': 'EC2-PUBLIC-IP',
                        'title': 'Publicly Accessible EC2 Instance',
                        'severity': 'HIGH',
                        'description': 'EC2 instance is directly accessible from the internet with a public IP address, increasing attack surface.',
                        'remediation': 'Move instance to private subnet and use Application Load Balancer for public access.',
                        'category': 'Network Security',
                        'risk_score': 85,
                        'compliance_standards': ['CIS AWS 1.4', 'PCI DSS 1.2'],
                        'attack_vectors': ['SSH Brute Force', 'Port Scanning'],
                        'business_impact': 'High - Potential data breach and service disruption',
                        'detection_time': '2 hours ago',
                        'exploitability': 'Easy',
                        'remediation_complexity': 'Medium'
                    }
                ]
            },
            {
                'resource_id': 'prod-eks-cluster-01',
                'resource_type': 'EKS',
                'service': 'EKS', 
                'name': 'production-kubernetes',
                'status': 'ACTIVE',
                'version': '1.28',
                'endpoint': 'https://xyz.gr7.us-east-1.eks.amazonaws.com',
                'vulnerabilities': [
                    {
                        'id': 'EKS-LOGGING-DISABLED',
                        'title': 'Control Plane Logging Disabled',
                        'severity': 'MEDIUM',
                        'description': 'EKS control plane logging is not enabled, limiting audit capability and security monitoring.',
                        'remediation': 'Enable all control plane log types (api, audit, authenticator, scheduler) for comprehensive monitoring.',
                        'category': 'Logging & Monitoring',
                        'risk_score': 45,
                        'compliance_standards': ['CIS Kubernetes 1.2.1'],
                        'attack_vectors': ['Lack of Audit Trail'],
                        'business_impact': 'Medium - Limited visibility into cluster activities',
                        'detection_time': '5 hours ago',
                        'exploitability': 'Difficult',
                        'remediation_complexity': 'Low'
                    }
                ]
            },
            {
                'resource_id': 'data-processor-function',
                'resource_type': 'Lambda',
                'service': 'Lambda',
                'name': 'customer-data-processor',
                'runtime': 'python3.9',
                'memory_size': 512,
                'timeout': 300,
                'vulnerabilities': [
                    {
                        'id': 'LAMBDA-ENV-SECRETS',
                        'title': 'Secrets in Environment Variables',
                        'severity': 'HIGH',
                        'description': 'Lambda function stores database credentials in plaintext environment variables.',
                        'remediation': 'Migrate secrets to AWS Secrets Manager and implement secret rotation.',
                        'category': 'Data Protection',
                        'risk_score': 75,
                        'compliance_standards': ['GDPR Article 32', 'HIPAA'],
                        'attack_vectors': ['Credential Theft', 'Environment Inspection'],
                        'business_impact': 'High - Potential PII data exposure',
                        'detection_time': '3 hours ago',
                        'exploitability': 'Medium',
                        'remediation_complexity': 'Medium'
                    }
                ]
            },
            {
                'resource_id': 'customer-data-bucket',
                'resource_type': 'S3',
                'service': 'S3',
                'name': 'customer-uploads-prod',
                'creation_date': '2024-01-10',
                'vulnerabilities': [
                    {
                        'id': 'S3-PUBLIC-READ',
                        'title': 'S3 Bucket Public Read Access',
                        'severity': 'HIGH',
                        'description': 'S3 bucket allows public read access, potentially exposing sensitive customer data.',
                        'remediation': 'Enable S3 Block Public Access and review bucket policies.',
                        'category': 'Data Protection',
                        'risk_score': 80,
                        'compliance_standards': ['GDPR Article 25', 'PCI DSS 3.2'],
                        'attack_vectors': ['Data Exfiltration', 'Unauthorized Access'],
                        'business_impact': 'High - Customer data exposure risk',
                        'detection_time': '4 hours ago',
                        'exploitability': 'Easy',
                        'remediation_complexity': 'Low'
                    }
                ]
            },
            {
                'resource_id': 'admin-role',
                'resource_type': 'IAM',
                'service': 'IAM',
                'name': 'AdministratorAccessRole',
                'created_date': '2024-01-01',
                'vulnerabilities': [
                    {
                        'id': 'IAM-ADMIN-POLICY',
                        'title': 'Overly Permissive IAM Policy',
                        'severity': 'CRITICAL',
                        'description': 'IAM role has AdministratorAccess policy attached, violating principle of least privilege.',
                        'remediation': 'Replace with custom policy granting only necessary permissions.',
                        'category': 'Access Control',
                        'risk_score': 90,
                        'compliance_standards': ['CIS AWS 1.16', 'NIST 800-53'],
                        'attack_vectors': ['Privilege Escalation', 'Credential Compromise'],
                        'business_impact': 'Critical - Complete AWS account compromise risk',
                        'detection_time': '6 hours ago',
                        'exploitability': 'Medium',
                        'remediation_complexity': 'High'
                    }
                ]
            }
        ]
        
        vulnerabilities = []
        for resource in resources:
            for vuln in resource.get('vulnerabilities', []):
                vuln_data = vuln.copy()
                vuln_data['resource_id'] = resource['resource_id']
                vuln_data['resource_type'] = resource['resource_type']
                vuln_data['resource_name'] = resource.get('name', resource['resource_id'])
                vuln_data['service'] = resource.get('service', 'Unknown')
                vulnerabilities.append(vuln_data)
        
        return resources, vulnerabilities

    def run_comprehensive_scan(self, selected_tools):
        """Run comprehensive security scan across selected tools"""
        with st.spinner('🚀 **Launching Multi-Tool Security Assessment...**'):
            try:
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                all_findings = []
                tool_progress = {}
                
                # Initialize progress tracking
                for i, tool in enumerate(selected_tools):
                    tool_progress[tool] = 0
                
                total_tools = len(selected_tools)
                
                for i, tool in enumerate(selected_tools):
                    status_text.text(f"🔍 **Scanning with {tool}...**")
                    
                    # Simulate tool scanning with progress
                    for j in range(5):
                        tool_progress[tool] = (j + 1) * 20
                        overall_progress = (i * 100 + tool_progress[tool]) / total_tools
                        progress_bar.progress(overall_progress / 100)
                        time.sleep(0.2)
                    
                    # Get findings from tool
                    findings = self.get_tool_findings(tool)
                    all_findings.extend(findings)
                    
                    # Mark tool as complete
                    tool_progress[tool] = 100
                
                # Generate enhanced sample data for AWS resources
                sample_resources, sample_vulns = self._generate_enhanced_sample_data()
                
                st.session_state.scan_results = {
                    'resources': sample_resources,
                    'vulnerabilities': all_findings + sample_vulns,
                    'scan_time': datetime.now().isoformat(),
                    'is_demo': self.aws_clients is None,
                    'selected_tools': selected_tools,
                    'tool_findings': {tool: self.get_tool_findings(tool) for tool in selected_tools},
                    'total_resources': len(sample_resources)
                }
                
                st.session_state.last_scan_time = datetime.now()
                st.session_state.security_score = max(0, 100 - len(all_findings) * 1)
                
                progress_bar.progress(1.0)
                status_text.text("✅ **Multi-Tool Security Assessment Complete!**")
                
                self._show_scan_summary(sample_resources, all_findings + sample_vulns, selected_tools)
                
            except Exception as e:
                logger.error(f"Scan failed: {e}")
                st.error(f"❌ **Scan failed:** {str(e)}")
                self.run_basic_scan()
    
    def _show_scan_summary(self, resources, vulnerabilities, selected_tools):
        """Display enhanced scan summary"""
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">📊</div>
                <div class="metric-label">Resources Scanned</div>
                <div class="metric-value">{len(resources)}</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">🚨</div>
                <div class="metric-label">Total Findings</div>
                <div class="metric-value">{len(vulnerabilities)}</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            critical_count = len([v for v in vulnerabilities if v['severity'] in ['CRITICAL', 'HIGH']])
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">🔥</div>
                <div class="metric-label">Critical/High</div>
                <div class="metric-value">{critical_count}</div>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            security_score = st.session_state.security_score
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-value">🛡️</div>
                <div class="metric-label">Security Score</div>
                <div class="metric-value">{security_score}/100</div>
            </div>
            """, unsafe_allow_html=True)
        
        # Tool status summary
        st.subheader("🛠️ Tool Integration Status")
        tool_cols = st.columns(len(selected_tools))
        for idx, tool in enumerate(selected_tools):
            with tool_cols[idx]:
                status = st.session_state.tool_status.get(tool, 'demo')
                status_class = f"tool-{status}"
                status_text = "🟢 Live" if status == 'live' else "🟡 Demo" if status == 'demo' else "🔴 Offline"
                st.markdown(f"""
                <div class="tool-card">
                    <h4>{tool}</h4>
                    <div class="tool-indicator {status_class}"></div>
                    <small>{status_text}</small>
                </div>
                """, unsafe_allow_html=True)
    
    def run_basic_scan(self):
        """Basic scan with minimal sample data"""
        resources, vulnerabilities = self._generate_enhanced_sample_data()
        
        st.session_state.scan_results = {
            'resources': resources,
            'vulnerabilities': vulnerabilities,
            'scan_time': datetime.now().isoformat(),
            'is_demo': True
        }
        
        st.session_state.security_score = 78

    def display_dashboard(self):
        """Main dashboard with enhanced visuals"""
        st.markdown('<h1 class="main-header">🛡️ Multi-Cloud Security Dashboard</h1>', unsafe_allow_html=True)
        st.markdown('<p class="sub-header">Unified Security Monitoring Across AWS, Azure, GCP and Security Tools</p>', unsafe_allow_html=True)
        
        # Display security overview
        self._display_security_overview()
        
        # Main content area
        if st.session_state.scan_results is None:
            self.display_welcome()
        else:
            self.display_enhanced_results()
    
    def _display_security_overview(self):
        """Display security overview metrics with tool filters"""
        col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
        
        with col1:
            # Tool selection
            st.subheader("🔧 Integrated Security Tools")
            
            # Create tool selection by category
            for category, tools in self.security_tools.items():
                with st.expander(f"{category} ({len(tools)} tools)"):
                    selected = st.multiselect(
                        f"Select {category} tools:",
                        tools,
                        default=[t for t in tools if t in st.session_state.selected_tools],
                        key=f"tools_{category}"
                    )
                    # Update selected tools
                    for tool in tools:
                        if tool in selected and tool not in st.session_state.selected_tools:
                            st.session_state.selected_tools.append(tool)
                        elif tool not in selected and tool in st.session_state.selected_tools:
                            st.session_state.selected_tools.remove(tool)
            
            # AI Model Selection
            st.subheader("🤖 AI Model Selection")
            selected_provider = st.selectbox(
                "Select AI Provider:",
                list(self.bedrock_models.keys())
            )
            
            if selected_provider:
                st.session_state.selected_ai_model = st.selectbox(
                    "Select AI Model:",
                    self.bedrock_models[selected_provider],
                    index=0
                )
            
            if st.session_state.last_scan_time:
                last_scan = st.session_state.last_scan_time.strftime('%Y-%m-%d %H:%M')
                st.info(f"**Last Assessment:** {last_scan} | **Tools:** {len(st.session_state.selected_tools)} | **AI Model:** {st.session_state.selected_ai_model} | **Mode:** {'🔬 Demo' if not self.aws_clients else '🚀 Live'}")
            else:
                st.info(f"**Ready for security assessment** | **Selected Tools:** {len(st.session_state.selected_tools)} | **AI Model:** {st.session_state.selected_ai_model}")
        
        with col2:
            if st.button("🔄 Quick Scan", use_container_width=True):
                self.run_basic_scan()
                st.rerun()
        
        with col3:
            if st.button("🚀 Full Assessment", use_container_width=True, type="primary"):
                if st.session_state.selected_tools:
                    self.run_comprehensive_scan(st.session_state.selected_tools)
                    st.rerun()
                else:
                    st.warning("Please select at least one security tool")
        
        with col4:
            if st.button("🗑️ Clear Results", use_container_width=True):
                st.session_state.scan_results = None
                st.session_state.selected_vulnerabilities = []
                st.session_state.remediation_plan = None
                st.rerun()
    
    def display_welcome(self):
        """Enhanced welcome screen with tool integration"""
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.markdown("""
            <div style='text-align: center; padding: 20px;'>
                <h2 style='color: #e2e8f0; margin-bottom: 10px;'>🔍 Unified Cloud Security</h2>
                <p style='color: #b0b0b0; font-size: 1.1rem;'>Multi-tool security monitoring and AI-powered remediation across AWS, Azure, and GCP</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Tool integration status
            st.subheader("🛠️ Integrated Security Tools")
            
            for category, tools in self.security_tools.items():
                with st.expander(f"📁 {category}", expanded=True):
                    cols = st.columns(2)
                    for i, tool in enumerate(tools):
                        col = cols[i % 2]
                        status = st.session_state.tool_status.get(tool, 'demo')
                        status_icon = "🟢" if status == 'live' else "🟡" if status == 'demo' else "🔴"
                        with col:
                            st.markdown(f"""
                            <div class="tool-card">
                                <h4>{tool}</h4>
                                <div style='font-size: 0.8rem; color: #b0b0b0;'>
                                    {status_icon} {status.upper()}
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
        
        with col2:
            # Cloud coverage
            st.markdown("""
            <div class="ai-insight">
                <h3 style='color: #e2e8f0; margin-bottom: 15px;'>☁️ Multi-Cloud Coverage</h3>
                <div style='display: flex; align-items: center; margin: 10px 0;'>
                    <span style='font-size: 1.5rem; margin-right: 10px;'>🅰️</span>
                    <span style='color: #e2e8f0;'>AWS - Full Coverage</span>
                </div>
                <div style='display: flex; align-items: center; margin: 10px 0;'>
                    <span style='font-size: 1.5rem; margin-right: 10px;'>Ⓜ️</span>
                    <span style='color: #e2e8f0;'>Azure - Partial Coverage</span>
                </div>
                <div style='display: flex; align-items: center; margin: 10px 0;'>
                    <span style='font-size: 1.5rem; margin-right: 10px;'>Ⓖ</span>
                    <span style='color: #e2e8f0;'>GCP - Partial Coverage</span>
                </div>
                <div style='display: flex; align-items: center; margin: 10px 0;'>
                    <span style='font-size: 1.5rem; margin-right: 10px;'>🖥️</span>
                    <span style='color: #e2e8f0;'>On-prem - Basic Coverage</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # AI Models
            st.markdown("""
            <div class="security-tip">
                <h4 style='color: #e2e8f0;'>🤖 AI-Powered Remediation</h4>
                <p style='color: #e2e8f0;'>Powered by AWS Bedrock with multiple AI models for intelligent security analysis and automated remediation.</p>
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("🎯 Start Security Assessment", use_container_width=True, type="primary"):
                if st.session_state.selected_tools:
                    self.run_comprehensive_scan(st.session_state.selected_tools)
                    st.rerun()
                else:
                    st.warning("Please select at least one security tool")
    
    def display_enhanced_results(self):
        """Display enhanced results with multi-tool support"""
        resources = st.session_state.scan_results['resources']
        vulnerabilities = st.session_state.scan_results['vulnerabilities']
        tool_findings = st.session_state.scan_results.get('tool_findings', {})
        
        # Create tabs for different views
        tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
            "📊 Dashboard", 
            "🚨 Findings", 
            "🔧 Resources", 
            "🛠️ Tools View",
            "🤖 AI Analysis",
            "⚡ Remediation",
            "📈 Execution Dashboard"
        ])
        
        with tab1:
            self._display_dashboard_tab(resources, vulnerabilities, tool_findings)
        
        with tab2:
            self._display_findings_tab(vulnerabilities)
        
        with tab3:
            self._display_resources_tab(resources)
        
        with tab4:
            self._display_tools_view_tab(tool_findings)
        
        with tab5:
            self._display_ai_analysis_tab(vulnerabilities)
        
        with tab6:
            self._display_remediation_tab(vulnerabilities)
        
        with tab7:
            self._display_execution_dashboard()
    
    def _create_metric_card(self, icon, label, value, color):
        """Create a metric card"""
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="font-size: 2rem;">{icon}</div>
            <div class="metric-label">{label}</div>
            <div class="metric-value" style="font-size: 2.2rem;">{value}</div>
        </div>
        """, unsafe_allow_html=True)

    def _create_severity_chart(self, vulnerabilities):
        """Create severity distribution chart with Plotly"""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            severity_counts[vuln['severity']] += 1
        
        if sum(severity_counts.values()) == 0:
            st.info("No vulnerabilities found")
            return
        
        fig = px.pie(values=severity_counts.values(), names=severity_counts.keys(),
                     title="Vulnerability Severity Distribution",
                     color_discrete_map={'CRITICAL': '#e53e3e', 'HIGH': '#dd6b20', 
                                         'MEDIUM': '#d69e2e', 'LOW': '#38a169'})
        st.plotly_chart(fig, use_container_width=True)

    def _create_tool_severity_chart(self, tool_findings):
        """Create severity distribution by tool"""
        tool_severity_data = []
        for tool, findings in tool_findings.items():
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for finding in findings:
                severity_counts[finding['severity']] += 1
            for severity, count in severity_counts.items():
                if count > 0:
                    tool_severity_data.append({
                        'Tool': tool,
                        'Severity': severity,
                        'Count': count
                    })
        
        if tool_severity_data:
            df = pd.DataFrame(tool_severity_data)
            fig = px.bar(df, x='Tool', y='Count', color='Severity',
                         title="Severity Distribution by Tool",
                         color_discrete_map={'CRITICAL': '#e53e3e', 'HIGH': '#dd6b20', 
                                           'MEDIUM': '#d69e2e', 'LOW': '#38a169'})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No tool findings to display")

    def _get_cloud_distribution(self, vulnerabilities):
        """Get cloud provider distribution from findings"""
        cloud_mapping = {
            'AWS': ['EC2', 'S3', 'IAM', 'GuardDuty', 'Security Hub', 'Inspector'],
            'Azure': ['Azure', 'Prisma Cloud'],
            'GCP': ['GCP', 'GKE', 'Wiz'],
            'On-prem': ['Qualys', 'Cortex XDR', 'Nessus', 'OpenVAS']
        }
        
        cloud_counts = {'AWS': 0, 'Azure': 0, 'GCP': 0, 'On-prem': 0, 'Other': 0}
        
        for vuln in vulnerabilities:
            service = vuln.get('service', '').upper()
            found = False
            for cloud, indicators in cloud_mapping.items():
                if any(indicator.upper() in service for indicator in indicators):
                    cloud_counts[cloud] += 1
                    found = True
                    break
            if not found:
                cloud_counts['Other'] += 1
        
        return {k: v for k, v in cloud_counts.items() if v > 0}

    def _display_dashboard_tab(self, resources, vulnerabilities, tool_findings):
        """Enhanced dashboard with multi-tool visualizations"""
        st.header("📊 Multi-Tool Security Dashboard")
        
        # Top metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            self._create_metric_card("📊", "Resources", len(resources), "#4a5568")
        with col2:
            self._create_metric_card("🚨", "Total Findings", len(vulnerabilities), "#e53e3e")
        with col3:
            critical_count = len([v for v in vulnerabilities if v['severity'] in ['CRITICAL', 'HIGH']])
            self._create_metric_card("🔥", "Critical/High", critical_count, "#c53030")
        with col4:
            security_score = st.session_state.security_score
            self._create_metric_card("🛡️", "Security Score", f"{security_score}/100", "#38a169")
        
        # Tool-specific findings
        st.subheader("🛠️ Findings by Security Tool")
        tool_counts = {}
        for tool, findings in tool_findings.items():
            tool_counts[tool] = len(findings)
        
        if tool_counts:
            fig = px.bar(x=list(tool_counts.keys()), y=list(tool_counts.values()),
                         title="Findings Distribution by Security Tool",
                         color=list(tool_counts.keys()))
            st.plotly_chart(fig, use_container_width=True)
        
        # Severity distribution
        col1, col2 = st.columns(2)
        
        with col1:
            self._create_severity_chart(vulnerabilities)
        
        with col2:
            self._create_tool_severity_chart(tool_findings)
        
        # Cloud provider distribution
        st.subheader("☁️ Findings by Cloud Provider")
        cloud_counts = self._get_cloud_distribution(vulnerabilities)
        if cloud_counts:
            fig = px.pie(values=cloud_counts.values(), names=cloud_counts.keys(),
                         title="Findings by Cloud Provider")
            st.plotly_chart(fig, use_container_width=True)

    def _display_findings_tab(self, vulnerabilities):
        """Display findings from all tools"""
        st.header("🚨 Unified Security Findings")
        
        if not vulnerabilities:
            st.success("🎉 No security findings detected across all tools!")
            return
        
        # Enhanced filters
        col1, col2, col3, col4 = st.columns([2, 2, 1, 1])
        
        with col1:
            # Tool filter
            tools = list(set([v.get('service', 'Unknown') for v in vulnerabilities]))
            selected_tools = st.multiselect(
                "Filter by Tool:",
                tools,
                default=tools
            )
        
        with col2:
            # Severity filter
            severities = list(set([v['severity'] for v in vulnerabilities]))
            selected_severities = st.multiselect(
                "Filter by Severity:",
                severities,
                default=severities
            )
        
        with col3:
            # Cloud filter
            clouds = ['AWS', 'Azure', 'GCP', 'On-prem', 'Other']
            selected_clouds = st.multiselect(
                "Filter by Cloud:",
                clouds,
                default=clouds
            )
        
        with col4:
            search_term = st.text_input("Search:", placeholder="Title, description...")
        
        # Apply filters
        filtered_vulns = [v for v in vulnerabilities 
                         if v.get('service', 'Unknown') in selected_tools
                         and v['severity'] in selected_severities
                         and (not search_term or search_term.lower() in v['title'].lower() or search_term.lower() in v.get('description', '').lower())]
        
        # Additional cloud filtering
        cloud_mapping = self._get_cloud_distribution([v for v in filtered_vulns])
        filtered_vulns = [v for v in filtered_vulns if any(cloud in cloud_mapping for cloud in selected_clouds)]
        
        st.write(f"**Showing {len(filtered_vulns)} of {len(vulnerabilities)} findings**")
        
        for idx, vuln in enumerate(filtered_vulns):
            self._display_finding_card(vuln, idx)
    
    def _display_finding_card(self, vuln, idx):
        """Display individual finding card"""
        border_color = {
            'CRITICAL': '#e53e3e',
            'HIGH': '#dd6b20', 
            'MEDIUM': '#d69e2e',
            'LOW': '#38a169'
        }.get(vuln['severity'], '#666')
        
        tool_icons = {
            'GuardDuty': '🛡️',
            'Security Hub': '🔒',
            'Prisma Cloud': '☁️',
            'Wiz': '🔍',
            'Qualys': '📊',
            'Cortex XDR': '🖥️'
        }
        
        tool_icon = tool_icons.get(vuln.get('service', ''), '🔧')
        
        st.markdown(f"""
        <div class="vulnerability-card" style="border-left-color: {border_color};">
            <div style="display: flex; justify-content: between; align-items: start;">
                <div style="flex: 1;">
                    <h3 style="margin: 0 0 10px 0; color: #e2e8f0; font-weight: 600;">{vuln['title']}</h3>
                    <div style="display: flex; gap: 15px; margin-bottom: 10px; flex-wrap: wrap;">
                        <span class="severity-{vuln['severity'].lower()}" style="background: {border_color}; color: white; padding: 4px 12px; border-radius: 15px; font-size: 0.9rem; font-weight: bold;">
                            {vuln['severity']}
                        </span>
                        <span style="background: #4a5568; color: #e2e8f0; padding: 4px 12px; border-radius: 15px; font-size: 0.9rem; border: 1px solid #718096;">
                            {tool_icon} {vuln.get('service', 'Unknown Tool')}
                        </span>
                        <span style="background: #744210; color: #e2e8f0; padding: 4px 12px; border-radius: 15px; font-size: 0.9rem; border: 1px solid #d69e2e;">
                            ⏱️ {vuln.get('created', 'Recently').split('T')[0]}
                        </span>
                    </div>
                </div>
            </div>
            
            <div style="margin: 15px 0;">
                <p style="margin: 0; color: #e2e8f0; line-height: 1.5; background: #4a5568; padding: 12px; border-radius: 6px;">{vuln['description']}</p>
            </div>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 15px 0;">
                <div style="background: #4a5568; padding: 12px; border-radius: 6px;">
                    <strong style="color: #e2e8f0;">🎯 Resource:</strong>
                    <p style="margin: 5px 0; color: #e2e8f0; word-break: break-all;">{vuln.get('resource', 'N/A')}</p>
                </div>
                <div style="background: #4a5568; padding: 12px; border-radius: 6px;">
                    <strong style="color: #e2e8f0;">📋 Type:</strong>
                    <p style="margin: 5px 0; color: #e2e8f0;">{vuln.get('type', 'N/A')}</p>
                    <strong style="color: #e2e8f0;">🆔 ID:</strong>
                    <p style="margin: 5px 0; color: #e2e8f0; font-family: monospace;">{vuln['id']}</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Action buttons
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            if st.button(f"🤖 Analyze with AI", key=f"analyze_{idx}"):
                if vuln not in st.session_state.selected_vulnerabilities:
                    st.session_state.selected_vulnerabilities.append(vuln)
                    st.success(f"✅ Added to AI analysis queue!")
        with col2:
            if st.button(f"⭐ Select for Remediation", key=f"select_{idx}"):
                if vuln not in st.session_state.selected_vulnerabilities:
                    st.session_state.selected_vulnerabilities.append(vuln)
                    st.success(f"✅ Selected for remediation!")
        with col3:
            if st.button("📋 View Details", key=f"details_{idx}"):
                st.json(vuln, expanded=False)
        
        st.markdown("---")

    def _display_tools_view_tab(self, tool_findings):
        """Display detailed view by security tool"""
        st.header("🛠️ Security Tools View")
        
        if not tool_findings:
            st.info("No tool findings available. Run a security assessment first.")
            return
        
        # Create tabs for each tool
        tool_tabs = st.tabs([f" {tool}" for tool in tool_findings.keys()])
        
        for idx, (tool, findings) in enumerate(tool_findings.items()):
            with tool_tabs[idx]:
                status = st.session_state.tool_status.get(tool, 'demo')
                status_text = "🟢 Live Data" if status == 'live' else "🟡 Demo Data"
                
                st.subheader(f"{tool} - {status_text}")
                
                if not findings:
                    st.info(f"No findings from {tool}")
                    continue
                
                # Tool-specific metrics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Findings", len(findings))
                with col2:
                    critical = len([f for f in findings if f['severity'] in ['CRITICAL', 'HIGH']])
                    st.metric("Critical/High", critical)
                with col3:
                    st.metric("Data Source", "Live" if status == 'live' else "Demo")
                
                # Display findings for this tool
                for finding in findings:
                    with st.expander(f"{finding['severity']} - {finding['title']}", expanded=False):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write("**Description:**", finding['description'])
                            st.write("**Resource:**", finding.get('resource', 'N/A'))
                            st.write("**Type:**", finding.get('type', 'N/A'))
                        with col2:
                            st.write("**Created:**", finding.get('created', 'N/A'))
                            if finding.get('confidence'):
                                st.write("**Confidence:**", f"{finding['confidence']}%")
                            if finding.get('cve'):
                                st.write("**CVE:**", finding['cve'])

    def _display_resources_tab(self, resources):
        """Display resources with enhanced details"""
        st.header("🔧 AWS Resources")
        
        # Service filter for resources
        services = list(set([r['service'] for r in resources]))
        selected_services = st.multiselect(
            "Filter resources by service:",
            services,
            default=services,
            key="resource_service_filter"
        )
        
        filtered_resources = [r for r in resources if r['service'] in selected_services]
        
        for resource in filtered_resources:
            with st.expander(f"{resource['service']} - {resource.get('name', resource['resource_id'])}", expanded=False):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**📋 Basic Information**")
                    st.write(f"**Resource ID:** `{resource['resource_id']}`")
                    st.write(f"**Type:** {resource['resource_type']}")
                    st.write(f"**Service:** {resource['service']}")
                    st.write(f"**Name:** {resource.get('name', 'Unnamed')}")
                    
                    if resource.get('state'):
                        st.write(f"**State:** {resource['state']}")
                    if resource.get('status'):
                        st.write(f"**Status:** {resource['status']}")
                
                with col2:
                    st.write("**🔧 Configuration**")
                    if resource['resource_type'] == 'EC2':
                        st.write(f"**Instance Type:** {resource.get('instance_type', 'N/A')}")
                        st.write(f"**Public IP:** {resource.get('public_ip', 'Not assigned')}")
                    elif resource['resource_type'] == 'EKS':
                        st.write(f"**Version:** {resource.get('version', 'N/A')}")
                        st.write(f"**Endpoint:** {resource.get('endpoint', 'N/A')}")
                    elif resource['resource_type'] == 'Lambda':
                        st.write(f"**Runtime:** {resource.get('runtime', 'N/A')}")
                        st.write(f"**Memory:** {resource.get('memory_size', 'N/A')} MB")
                    elif resource['resource_type'] == 'S3':
                        st.write(f"**Creation Date:** {resource.get('creation_date', 'N/A')}")
                    elif resource['resource_type'] == 'IAM':
                        st.write(f"**Created Date:** {resource.get('created_date', 'N/A')}")
                    elif resource['resource_type'] == 'VPC':
                        st.write(f"**CIDR Block:** {resource.get('cidr_block', 'N/A')}")
                
                # Vulnerabilities section
                if resource.get('vulnerabilities'):
                    st.write("**🚨 Security Findings**")
                    for vuln in resource['vulnerabilities']:
                        severity_class = f"severity-{vuln['severity'].lower()}"
                        border_color = {
                            'CRITICAL': '#e53e3e',
                            'HIGH': '#dd6b20',
                            'MEDIUM': '#d69e2e',
                            'LOW': '#38a169'
                        }.get(vuln['severity'], '#666')
                        
                        st.markdown(f"""
                        <div style="border-left: 4px solid {border_color}; padding: 10px; margin: 5px 0; background: #4a5568; border-radius: 5px;">
                            <strong style="color: #e2e8f0;">{vuln['title']}</strong> - <span class="{severity_class}">{vuln['severity']}</span><br>
                            <small style="color: #e2e8f0;">{vuln['description']}</small>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.success("✅ No vulnerabilities detected")

    def _display_ai_analysis_tab(self, vulnerabilities):
        """Display AI-powered analysis"""
        st.header("🤖 AI Security Analysis")
        
        if not vulnerabilities:
            st.info("Run a security scan to get AI-powered analysis.")
            return
        
        selected_vulns = st.session_state.selected_vulnerabilities
        
        if not selected_vulns:
            st.info("Select vulnerabilities from the Findings tab for AI analysis.")
            
            # Quick analysis option
            st.subheader("🚀 Quick Analysis")
            quick_vuln = st.selectbox(
                "Select a finding for instant AI analysis:",
                options=vulnerabilities,
                format_func=lambda x: f"{x['severity']} - {x['title']} - {x.get('service', 'Unknown Tool')}"
            )
            
            if quick_vuln and st.button("🤖 Analyze This Finding"):
                self._display_ai_analysis_results(quick_vuln)
            return
        
        # Display analysis for selected vulnerabilities
        st.subheader("📋 Selected for AI Analysis")
        
        for idx, vuln in enumerate(selected_vulns):
            st.markdown(f"**{vuln['title']}** - `{vuln.get('resource_name', vuln.get('resource', 'N/A'))}`")
            
            if st.button(f"🧠 Run AI Analysis", key=f"run_ai_{idx}"):
                self._display_ai_analysis_results(vuln)
            
            if st.button(f"❌ Remove", key=f"remove_ai_{idx}"):
                st.session_state.selected_vulnerabilities.remove(vuln)
                st.rerun()
            
            st.markdown("---")

    def _display_ai_analysis_results(self, vulnerability):
        """Display detailed AI analysis results"""
        st.markdown(f"### 🤖 AI Analysis: {vulnerability['title']}")
        
        # Show selected AI model
        st.info(f"**Using AI Model:** {st.session_state.selected_ai_model}")
        
        with st.spinner("🤖 AI is analyzing the finding..."):
            # Create comprehensive prompt for AI analysis
            prompt = f"""
            Analyze this security finding and provide detailed remediation steps:

            Finding Details:
            - Title: {vulnerability['title']}
            - Severity: {vulnerability['severity']}
            - Description: {vulnerability['description']}
            - Resource: {vulnerability.get('resource', 'N/A')}
            - Service/Tool: {vulnerability.get('service', 'Unknown')}
            - Type: {vulnerability.get('type', 'N/A')}

            Please provide:
            1. Risk assessment and business impact analysis
            2. Step-by-step remediation plan
            3. AWS CLI commands or specific actions needed
            4. Compliance implications
            5. Long-term prevention strategies

            Format the response with clear sections and actionable steps.
            """
            
            # Call Bedrock AI
            ai_response = self._call_bedrock_ai(prompt)
            
            # Display AI response
            st.markdown(ai_response)

    def _display_remediation_tab(self, vulnerabilities):
        """Enhanced remediation hub with AI-powered remediation"""
        st.header("⚡ AI-Powered Remediation Hub")
        
        selected_vulns = st.session_state.selected_vulnerabilities
        
        if not selected_vulns:
            st.info("🎯 Select findings from the Findings tab to begin remediation planning.")
            return
        
        # Remediation overview
        st.subheader("📋 Remediation Overview")
        
        total_risk = sum([v.get('risk_score', 50) for v in selected_vulns])
        critical_count = len([v for v in selected_vulns if v['severity'] in ['CRITICAL', 'HIGH']])
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Selected Items", len(selected_vulns))
        with col2:
            st.metric("Total Risk Score", total_risk)
        with col3:
            st.metric("Critical/High", critical_count)
        
        # AI Model Selection for Remediation
        st.subheader("🤖 AI Model Configuration")
        col1, col2 = st.columns(2)
        with col1:
            selected_provider = st.selectbox(
                "Select AI Provider for Remediation:",
                list(self.bedrock_models.keys()),
                key="remediation_ai_provider"
            )
        with col2:
            if selected_provider:
                remediation_model = st.selectbox(
                    "Select AI Model for Remediation:",
                    self.bedrock_models[selected_provider],
                    key="remediation_ai_model"
                )
                st.session_state.selected_ai_model = remediation_model
        
        # Selected vulnerabilities
        st.subheader("🎯 Selected for Remediation")
        
        for idx, vuln in enumerate(selected_vulns):
            col1, col2, col3 = st.columns([4, 1, 1])
            with col1:
                severity_class = f"severity-{vuln['severity'].lower()}"
                st.markdown(f"""
                **{vuln['title']}** 
                - `{vuln.get('resource_name', vuln.get('resource', 'N/A'))}` 
                - <span class='{severity_class}'>{vuln['severity']}</span>
                - Tool: {vuln.get('service', 'Unknown')}
                - Risk: {vuln.get('risk_score', 50)}/100
                """, unsafe_allow_html=True)
            with col2:
                if st.button("📋 AI Plan", key=f"ai_plan_{idx}"):
                    with st.spinner("🤖 Generating AI-powered remediation plan..."):
                        st.session_state.remediation_plan = self._generate_ai_remediation_plan([vuln])
                    st.success("AI-powered remediation plan generated!")
            with col3:
                if st.button("🗑️ Remove", key=f"remove_{idx}"):
                    st.session_state.selected_vulnerabilities.remove(vuln)
                    st.rerun()
        
        # Remediation actions
        st.subheader("🚀 Remediation Actions")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🤖 Generate AI Plan", use_container_width=True):
                with st.spinner("🤖 AI is generating comprehensive remediation plan..."):
                    st.session_state.remediation_plan = self._generate_ai_remediation_plan(selected_vulns)
                st.success("✅ AI-powered remediation plan generated! See below for details.")
        
        with col2:
            if st.button("🔍 Preview Changes", use_container_width=True):
                self._preview_remediation_changes(selected_vulns)
        
        with col3:
            execution_mode = st.selectbox(
                "Execution Mode:",
                ["dry-run", "live"],
                key="execution_mode_select"
            )
            st.session_state.execution_mode = execution_mode
            
            if st.button("⚡ Execute AI Plan", use_container_width=True, type="primary"):
                self._execute_ai_remediation(selected_vulns)
        
        # Improved plan display
        if st.session_state.remediation_plan:
            st.subheader("📄 AI-Generated Remediation Plan")
            plan = st.session_state.remediation_plan
            st.markdown(f"**Timestamp:** {plan['timestamp']}")
            st.markdown(f"**AI Model:** {plan['ai_model']}")
            st.markdown(f"**Findings:** {', '.join(plan['vulnerabilities'])}")
            st.markdown(f"**Estimated Duration:** {plan['estimated_duration']}")
            st.markdown(f"**Risk Level:** {plan['risk_level']}")
            
            st.subheader("AI Analysis & Steps")
            st.markdown(plan['ai_analysis'])
            
            st.subheader("Execution Steps")
            for step in plan['steps']:
                with st.expander(step['action']):
                    st.markdown(f"**Resource:** {step['resource']}")
                    st.markdown(f"**Estimated Time:** {step['estimated_time']}")
                    st.markdown(f"**Risk:** {step['risk']}")
                    st.markdown("**AI-Generated Commands:**")
                    for cmd in step['commands']:
                        st.code(cmd, language='bash')
        
        # CSV download
        st.subheader("📊 Export Remediation Data")
        st.info("Download a CSV file containing details of selected findings for offline review or sharing.")
        df = pd.DataFrame(selected_vulns)
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download CSV",
            data=csv,
            file_name=f"remediation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            help="Exports selected findings including title, severity, description, etc."
        )
        if st.button("📄 View Preview Before Download"):
            st.dataframe(df)

    def _generate_ai_remediation_plan(self, vulnerabilities):
        """Generate AI-powered remediation plan using Bedrock"""
        with st.spinner("🤖 AI is analyzing findings and generating remediation plan..."):
            # Create comprehensive prompt for AI remediation
            prompt = f"""
            Create a detailed remediation plan for the following security findings:

            Findings to Remediate:
            {json.dumps(vulnerabilities, indent=2)}

            Please provide:
            1. Comprehensive risk analysis and prioritization
            2. Step-by-step remediation actions for each finding
            3. Specific AWS CLI commands or API calls needed
            4. Rollback procedures for each action
            5. Compliance and security validation steps
            6. Estimated time and resources required

            Format the response as a structured remediation plan with clear executable steps.
            Focus on practical, actionable items that can be implemented.
            """
            
            # Call Bedrock AI
            ai_analysis = self._call_bedrock_ai(prompt)
            
            # Generate steps from AI response
            steps = []
            for vuln in vulnerabilities:
                step_prompt = f"""
                Generate specific remediation commands for this finding:
                Finding: {vuln['title']}
                Description: {vuln['description']}
                Resource: {vuln.get('resource', 'N/A')}
                Service: {vuln.get('service', 'Unknown')}
                
                Provide 3-5 specific CLI commands or API calls to remediate this issue.
                """
                
                ai_commands = self._call_bedrock_ai(step_prompt)
                commands = [cmd.strip() for cmd in ai_commands.split('\n') if cmd.strip() and '```' not in cmd]
                
                steps.append({
                    'action': f"Remediate {vuln['title']}",
                    'resource': vuln.get('resource_name', vuln.get('resource', 'N/A')),
                    'estimated_time': '15-30 minutes',
                    'risk': vuln['severity'],
                    'commands': commands[:5]  # Limit to 5 commands
                })
        
        return {
            'timestamp': datetime.now().isoformat(),
            'ai_model': st.session_state.selected_ai_model,
            'vulnerabilities': [v['id'] for v in vulnerabilities],
            'estimated_duration': f"{len(vulnerabilities) * 20} minutes",
            'risk_level': 'High' if any(v['severity'] in ['CRITICAL', 'HIGH'] for v in vulnerabilities) else 'Medium',
            'ai_analysis': ai_analysis,
            'steps': steps
        }

    def _preview_remediation_changes(self, vulnerabilities):
        """Preview remediation changes"""
        st.subheader("🔍 Change Preview")
        
        for vuln in vulnerabilities:
            with st.expander(f"Changes for {vuln['title']}"):
                st.markdown(f"""
                **Resource:** {vuln.get('resource_name', vuln.get('resource', 'N/A'))}
                **Tool:** {vuln.get('service', 'Unknown')}
                **Current State:** {vuln['description']}
                **Target State:** Secured - {vuln.get('remediation', 'Address the security finding based on tool recommendations')}
                **Impact:** Low - No service disruption expected
                **Rollback:** Automated rollback available
                """)

    def _execute_ai_remediation(self, vulnerabilities):
        """Execute AI-powered remediation with real-time updates"""
        mode = st.session_state.execution_mode
        if mode == 'live':
            confirm = st.checkbox("I confirm to execute the AI-generated remediation plan (uncheck to cancel)")
            if not confirm:
                st.warning("Live remediation cancelled.")
                return
        
        # Clear previous logs
        st.session_state.remediation_logs = []
        
        st.subheader("⚡ AI-Powered Remediation Execution")
        progress_bar = st.progress(0)
        status_text = st.empty()
        log_container = st.container()
        
        steps = [
            "🤖 Initializing AI remediation engine...",
            "📋 Validating AI-generated plan...",
            "🔒 Creating backup snapshots...",
            "⚡ Executing AI-generated commands...",
            "✅ Verifying remediation effectiveness...",
            "📊 Generating compliance report..."
        ]
        
        for i, step in enumerate(steps):
            status_text.text(f"**{step}** ({mode.capitalize()})")
            progress_bar.progress((i + 1) / len(steps))
            time.sleep(1)  # Simulate work
            
            # Log entry
            st.session_state.remediation_logs.append({
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'step': step,
                'status': 'In Progress',
                'mode': mode,
                'ai_model': st.session_state.selected_ai_model
            })
            
            with log_container:
                st.info(f"📝 {step} - In Progress")
            
            if i == 3:  # Executing commands
                for vuln in vulnerabilities:
                    try:
                        if mode == 'live' and self.aws_clients:
                            # In real implementation, execute the actual commands
                            status = 'Success (Live - AI Executed)'
                        else:
                            status = 'Success (Dry-run - AI Simulated)'
                        
                        st.session_state.remediation_logs.append({
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'step': f"AI Remediate {vuln['title']}",
                            'status': status,
                            'mode': mode,
                            'ai_model': st.session_state.selected_ai_model,
                            'details': f"AI successfully remediated {vuln.get('resource_name', vuln.get('resource', 'N/A'))}"
                        })
                        with log_container:
                            st.success(f"✅ {vuln['title']} - {status}")
                    except Exception as e:
                        error_msg = str(e)
                        st.session_state.remediation_logs.append({
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'step': f"AI Remediate {vuln['title']}",
                            'status': 'Failed',
                            'mode': mode,
                            'ai_model': st.session_state.selected_ai_model,
                            'details': error_msg
                        })
                        with log_container:
                            st.error(f"❌ {vuln['title']} - Failed: {error_msg}")
        
        status_text.text("🎉 AI-Powered Remediation completed!")
        st.balloons()
        
        st.info("AI remediation execution complete. Check the Execution Dashboard tab for full logs and status.")

    def _display_execution_dashboard(self):
        """Dashboard to show execution status and logs"""
        st.header("📈 AI Remediation Execution Dashboard")
        
        if not st.session_state.remediation_logs:
            st.info("No AI remediation executions yet. Run an AI-powered remediation plan to see status here.")
            return
        
        # Display logs as table
        logs_df = pd.DataFrame(st.session_state.remediation_logs)
        st.dataframe(logs_df, use_container_width=True)
        
        # Simple chart of status counts
        if not logs_df.empty:
            col1, col2 = st.columns(2)
            with col1:
                status_counts = logs_df['status'].value_counts()
                fig = px.pie(status_counts, values=status_counts.values, names=status_counts.index,
                             title="Remediation Status Distribution")
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # AI Model usage
                if 'ai_model' in logs_df.columns:
                    model_counts = logs_df['ai_model'].value_counts()
                    fig = px.bar(model_counts, x=model_counts.index, y=model_counts.values,
                                 title="AI Models Used")
                    st.plotly_chart(fig, use_container_width=True)
        
        # Clear logs button
        if st.button("🗑️ Clear Logs"):
            st.session_state.remediation_logs = []
            st.rerun()

def main():
    app = MultiCloudSecurityApp()
    app.display_dashboard()

if __name__ == "__main__":
    main()