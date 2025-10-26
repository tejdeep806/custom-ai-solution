import logging
import os

def setup_logging():
    """Setup application logging"""
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('aws_remediator.log')
        ]
    )
    
    return logging.getLogger(__name__)