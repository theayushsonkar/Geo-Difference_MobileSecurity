"""Logger configuration."""
import logging

def get_logger(name: str) -> logging.Logger:
    """Configures and returns a Python logger instance.
    
    Args:
        name (str): The name of the logger, typically __name__.
        
    Returns:
        logging.Logger: The configured logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(name)s | %(message)s')
        
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)
        
        logger.addHandler(ch)
    return logger
