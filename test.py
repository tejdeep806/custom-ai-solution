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

# Clean, Simple CSS - No complex themes, just proper visibility
st.markdown("""
<style>
    /* Reset everything to clean, visible defaults */
    .stApp {
        background-color: white !important;
    }
    
    /* Ensure ALL text is visible */
    .stMarkdown, .stText, .stTitle, .stHeader, 
    [data-testid="stMarkdownContainer"], .css-1lcbmhc, .css-1d391kg,
    p, div, span, h1, h2, h3, h4, h5, h6 {
        color: #000000 !important;
    }
    
    /* Fix sidebar text */
    .css-1d391kg, .css-1lcbmhc {
        background-color: #f0f2f6 !important;
    }
    
    .css-1d391kg p, .css-1lcbmhc p, 
    .css-1d391kg h1, .css-1d391kg h2, .css-1d391kg h3,
    .css-1lcbmhc h1, .css-1lcbmhc h2, .css-1lcbmhc h3 {
        color: #000000 !important;
    }
    
    /* Fix tabs */
    .stTabs [data-baseweb="tab"] {
        color: #000000 !important;
        background-color: #f0f2f6 !important;
    }
    
    .stTabs [aria-selected="true"] {
        color: #000000 !important;
        background-color: white !important;
        border: 1px solid #e0e0e0 !important;
    }
    
    /* Fix buttons */
    .stButton button {
        background-color: #1f77b4 !important;
        color: white !important;
        border: none !important;
        padding: 0.5rem 1rem !important;
        border-radius: 4px !important;
        font-weight: 600 !important;
    }
    
    /* Fix input fields */
    .stSelectbox, .stMultiselect, .stTextInput, .stTextArea {
        color: #000000 !important;
    }
    
    .stSelectbox div, .stMultiselect div {
        color: #000000 !important;
    }
    
    /* Fix metric cards */
    [data-testid="stMetricValue"], [data-testid="stMetricLabel"] {
        color: #000000 !important;
    }
    
    /* Simple header styling */
    .main-header {
        font-size: 2.5rem;
        color: #000000 !important;
        text-align: center;
        margin-bottom: 1rem;
        font-weight: 700;
        padding: 1rem;
    }
    
    .sub-header {
        font-size: 1.2rem;
        color: #666666 !important;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    /* Simple severity badges */
    .severity-critical { 
        background: #ff4444; 
        color: white !important; 
        padding: 4px 12px; 
        border-radius: 12px; 
        font-weight: bold;
        font-size: 0.8rem;
    }
    
    .severity-high { 
        background: #ff6b35; 
        color: white !important; 
        padding: 4px 12px; 
        border-radius: 12px; 
        font-weight: bold;
        font-size: 0.8rem;
    }
    
    .severity-medium { 
        background: #ffa500; 
        color: black !important; 
        padding: 4px 12px; 
        border-radius: 12px; 
        font-weight: bold;
        font-size: 0.8rem;
    }
    
    .severity-low { 
        background: #4CAF50; 
        color: white !important; 
        padding: 4px 12px; 
        border-radius: 12px; 
        font-weight: bold;
        font-size: 0.8rem;
    }
    
    /* Simple card styling */
    .vulnerability-card {
        background: #ffffff !important;
        border-radius: 8px;
        padding: 16px;
        margin: 12px 0;
        border-left: 4px solid #1f77b4;
        border: 1px solid #e0e0e0;
        color: #000000 !important;
    }
    
    /* Simple metric cards */
    .metric-card {
        background: #f8f9fa;
        color: #000000 !important;
        padding: 20px;
        border-radius: 8px;
        text-align: center;
        margin: 8px;
        border: 1px solid #dee2e6;
    }
    
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        margin: 8px 0;
        color: #000000 !important;
    }
    
    .metric-label {
        font-size: 0.9rem;
        color: #666666 !important;
    }
    
    /* Simple tool cards */
    .tool-card {
        background: #f8f9fa;
        color: #000000 !important;
        padding: 12px;
        border-radius: 6px;
        margin: 6px;
        border: 1px solid #dee2e6;
        text-align: center;
    }
    
    /* Make expanders visible */
    .stExpander {
        background-color: #ffffff !important;
        border: 1px solid #e0e0e0 !important;
    }
    
    .stExpander label {
        color: #000000 !important;
        font-weight: 600;
    }
    
    /* Ensure all content areas have proper background */
    .main .block-container {
        background-color: white !important;
        color: #000000 !important;
    }
    
    /* Fix any remaining dark elements */
    div[data-testid="stExpander"] div {
        color: #000000 !important;
    }
    
    /* Make sure all text in widgets is visible */
    .st-bb, .st-bc, .st-bd, .st-be, .st-bf, .st-bg, .st-bh, .st-bi, .st-bj, .st-bk, .st-bl, .st-bm, .st-bn, .st-bo, .st-bp, .st-bq, .st-br, .st-bs, .st-bt, .st-bu, .st-bv, .st-bw, .st-bx, .st-by, .st-bz {
        color: #000000 !important;
    }
</style>
""", unsafe_allow_html=True)

# ... REST OF YOUR ORIGINAL PYTHON CODE REMAINS EXACTLY THE SAME ...
# Just replace the CSS section above and keep all your Python code below

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
            'security_score': 85,
            'last_scan_time': None,
            'trend_data': self._generate_trend_data(),
            'service_filter': ['EC2', 'EKS', 'Lambda', 'S3', 'IAM'],
            'tool_status': self._initialize_tool_status()
        }
        
        for key, value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = value

    # ... ALL YOUR EXISTING METHODS CONTINUE EXACTLY AS THEY WERE ...
    # Keep all your existing Python code exactly as it was

    def display_dashboard(self):
        """Main dashboard with clean, visible styling"""
        st.markdown('<h1 class="main-header">🛡️ Multi-Cloud Security Dashboard</h1>', unsafe_allow_html=True)
        st.markdown('<p class="sub-header">Unified Security Monitoring Across AWS, Azure, GCP and Security Tools</p>', unsafe_allow_html=True)
        
        # Display security overview
        self._display_security_overview()
        
        # Main content area
        if st.session_state.scan_results is None:
            self.display_welcome()
        else:
            self.display_enhanced_results()

    # ... ALL YOUR OTHER METHODS REMAIN EXACTLY THE SAME ...

def main():
    app = MultiCloudSecurityApp()
    app.display_dashboard()

if __name__ == "__main__":
    main()