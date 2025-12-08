import logging
import os
import sys
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from typing import Optional
import json
from datetime import datetime


"""
Industrial-Level Logging Configuration for Flask Application
File: Backend/app/utils/logger_config.py

Features:
- Multiple log handlers (console, file, error, daily)
- Automatic log rotation by size and time
- Structured logging with detailed context
- Environment-based configuration
- Performance optimized
- Production-ready
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from typing import Optional
import json
from datetime import datetime


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter with colors for console output (development only)
    Makes logs easier to read during development
    """
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    def format(self, record):
        # Add color to log level
        if record.levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[record.levelname]}{record.levelname}"
                f"{self.COLORS['RESET']}"
            )
        return super().format(record)


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging (production)
    Makes logs easy to parse by log aggregation tools like ELK, Datadog, etc.
    """
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, 'user_id'):
            log_data['user_id'] = record.user_id
        if hasattr(record, 'request_id'):
            log_data['request_id'] = record.request_id
        
        return json.dumps(log_data)


class LoggerConfig:
    """
    Centralized logging configuration manager
    Handles all logging setup for the application
    """
    
    # Default configuration
    DEFAULT_LOG_DIR = 'logs'
    DEFAULT_LOG_LEVEL = 'INFO'
    DEFAULT_LOG_FORMAT = '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s'
    DEFAULT_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    
    # File size limits
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
    BACKUP_COUNT = 10  # Keep 10 backup files
    DAILY_BACKUP_COUNT = 30  # Keep 30 days of daily logs
    
    @classmethod
    def setup(cls, app=None, log_dir: Optional[str] = None, 
              log_level: Optional[str] = None, json_logs: bool = False):
        """
        Setup application-wide logging configuration
        
        Args:
            app: Flask application instance (optional)
            log_dir: Directory to store log files (default: 'logs')
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            json_logs: Use JSON formatting for logs (recommended for production)
        
        Returns:
            None
        
        Example:
            # In your app/__init__.py
            LoggerConfig.setup(app, log_level='INFO')
        """
        
        # Get configuration from environment or use defaults
        log_dir = log_dir or os.getenv('LOG_DIR', cls.DEFAULT_LOG_DIR)
        log_level = log_level or os.getenv('LOG_LEVEL', cls.DEFAULT_LOG_LEVEL)
        json_logs = json_logs or os.getenv('JSON_LOGS', 'false').lower() == 'true'
        
        # Create logs directory
        cls._create_log_directory(log_dir)
        
        # Get log level
        level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Create formatters
        if json_logs:
            # Use JSON formatter for production
            file_formatter = JSONFormatter()
            console_formatter = logging.Formatter(cls.DEFAULT_LOG_FORMAT, cls.DEFAULT_DATE_FORMAT)
        else:
            # Use colored formatter for development
            file_formatter = logging.Formatter(cls.DEFAULT_LOG_FORMAT, cls.DEFAULT_DATE_FORMAT)
            console_formatter = ColoredFormatter(cls.DEFAULT_LOG_FORMAT, cls.DEFAULT_DATE_FORMAT)
        
        # Setup handlers
        handlers = cls._create_handlers(log_dir, level, file_formatter, console_formatter)
        
        # Configure root logger
        cls._configure_root_logger(level, handlers)
        
        # Configure Flask app logger if provided
        if app:
            cls._configure_app_logger(app, handlers)
        
        # Reduce noise from third-party libraries
        cls._configure_third_party_loggers()
        
        # Log initialization message
        logger = logging.getLogger(__name__)
        logger.info("=" * 80)
        logger.info("🚀 Logging System Initialized")
        logger.info(f"📁 Log Directory: {os.path.abspath(log_dir)}")
        logger.info(f"📊 Log Level: {log_level}")
        logger.info(f"📝 JSON Logs: {json_logs}")
        logger.info("=" * 80)
    
    @staticmethod
    def _create_log_directory(log_dir: str) -> None:
        """Create log directory if it doesn't exist"""
        Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def _create_handlers(cls, log_dir: str, level: int, 
                         file_formatter, console_formatter) -> list:
        """Create and configure all log handlers"""
        handlers = []
        
        # 1. CONSOLE HANDLER (stdout)
        # Shows logs in terminal - useful for development and Docker
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(console_formatter)
        console_handler.name = 'console'
        handlers.append(console_handler)
        
        # 2. GENERAL APPLICATION LOG (rotating by size)
        # All INFO+ logs go here, rotates when file reaches 10MB
        app_handler = RotatingFileHandler(
            filename=os.path.join(log_dir, 'app.log'),
            maxBytes=cls.MAX_LOG_SIZE,
            backupCount=cls.BACKUP_COUNT,
            encoding='utf-8'
        )
        app_handler.setLevel(logging.INFO)
        app_handler.setFormatter(file_formatter)
        app_handler.name = 'app_file'
        handlers.append(app_handler)
        
        # 3. ERROR LOG (rotating by size)
        # Only ERROR+ logs go here for quick error checking
        error_handler = RotatingFileHandler(
            filename=os.path.join(log_dir, 'error.log'),
            maxBytes=cls.MAX_LOG_SIZE,
            backupCount=cls.BACKUP_COUNT,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        error_handler.name = 'error_file'
        handlers.append(error_handler)
        
        # 4. DEBUG LOG (rotating by size)
        # Detailed DEBUG+ logs for troubleshooting
        debug_handler = RotatingFileHandler(
            filename=os.path.join(log_dir, 'debug.log'),
            maxBytes=cls.MAX_LOG_SIZE,
            backupCount=5,  # Keep fewer debug logs
            encoding='utf-8'
        )
        debug_handler.setLevel(logging.DEBUG)
        debug_handler.setFormatter(file_formatter)
        debug_handler.name = 'debug_file'
        handlers.append(debug_handler)
        
        # 5. DAILY LOG (rotating by time)
        # Creates new log file every midnight, keeps 30 days
        daily_handler = TimedRotatingFileHandler(
            filename=os.path.join(log_dir, 'daily.log'),
            when='midnight',
            interval=1,
            backupCount=cls.DAILY_BACKUP_COUNT,
            encoding='utf-8'
        )
        daily_handler.setLevel(logging.INFO)
        daily_handler.setFormatter(file_formatter)
        daily_handler.name = 'daily_file'
        # Add date suffix to rotated files
        daily_handler.suffix = '%Y-%m-%d'
        handlers.append(daily_handler)
        
        return handlers
    
    @staticmethod
    def _configure_root_logger(level: int, handlers: list) -> None:
        """Configure the root logger"""
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        
        # Remove existing handlers
        root_logger.handlers.clear()
        
        # Add new handlers
        for handler in handlers:
            root_logger.addHandler(handler)
    
    @staticmethod
    def _configure_app_logger(app, handlers: list) -> None:
        """Configure Flask application logger"""
        app.logger.handlers.clear()
        
        for handler in handlers:
            app.logger.addHandler(handler)
        
        app.logger.setLevel(logging.INFO)
        app.logger.propagate = False  # Don't propagate to root logger
    
    @staticmethod
    def _configure_third_party_loggers() -> None:
        """Reduce noise from third-party libraries"""
        # Flask's built-in server logs
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
        
        # HTTP requests library
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
        
        # SQLAlchemy (if used)
        logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
        
        # Boto3 / AWS SDK (if used)
        logging.getLogger('boto3').setLevel(logging.WARNING)
        logging.getLogger('botocore').setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module
    
    Args:
        name: Logger name (usually __name__ of the module)
    
    Returns:
        Logger instance
    
    Example:
        from app.utils.logger_config import get_logger
        
        logger = get_logger(__name__)
        logger.info("This is an info message")
        logger.error("This is an error message", exc_info=True)
    """
    return logging.getLogger(name)


def log_function_call(func):
    """
    Decorator to automatically log function entry and exit
    Useful for tracking execution flow
    
    Example:
        @log_function_call
        def my_function(x, y):
            return x + y
    """
    import functools
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        logger.debug(f"Entering {func.__name__}() with args={args}, kwargs={kwargs}")
        
        try:
            result = func(*args, **kwargs)
            logger.debug(f"Exiting {func.__name__}() with result={result}")
            return result
        except Exception as e:
            logger.error(f"Exception in {func.__name__}(): {str(e)}", exc_info=True)
            raise
    
    return wrapper


# Example usage in your code:
if __name__ == '__main__':
    # Test the logging configuration
    LoggerConfig.setup(log_level='DEBUG')
    
    logger = get_logger(__name__)
    
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")
    
    try:
        1 / 0
    except Exception as e:
        logger.error("An error occurred", exc_info=True)