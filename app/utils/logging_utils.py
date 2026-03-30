"""
Structured logging and error handling utilities
"""

import logging
import json
import traceback
from typing import Any, Dict, Optional
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path


class JSONFormatter(logging.Formatter):
    """JSON structured logging formatter"""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info)
            }

        # Add extra fields
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)

        return json.dumps(log_data)


class StructuredLogger:
    """Enhanced logger with structured logging support"""

    def __init__(self, name: str, log_file: Optional[str] = None,
                 level: int = logging.INFO):
        """
        Initialize structured logger.
        
        Args:
            name: Logger name
            log_file: Optional log file path
            level: Logging level
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(JSONFormatter())
        self.logger.addHandler(console_handler)

        # Add file handler if specified
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=10
            )
            file_handler.setFormatter(JSONFormatter())
            self.logger.addHandler(file_handler)

    def log_with_context(self, level: int, message: str, **context) -> None:
        """Log message with additional context"""
        record = self.logger.makeRecord(
            self.logger.name,
            level,
            "(unknown file)",
            0,
            message,
            (),
            None
        )
        record.extra_data = context
        self.logger.handle(record)

    def debug(self, message: str, **context) -> None:
        self.log_with_context(logging.DEBUG, message, **context)

    def info(self, message: str, **context) -> None:
        self.log_with_context(logging.INFO, message, **context)

    def warning(self, message: str, **context) -> None:
        self.log_with_context(logging.WARNING, message, **context)

    def error(self, message: str, exception: Optional[Exception] = None,
              **context) -> None:
        if exception:
            self.logger.error(message, exc_info=exception)
        else:
            self.log_with_context(logging.ERROR, message, **context)

    def critical(self, message: str, exception: Optional[Exception] = None,
                 **context) -> None:
        if exception:
            self.logger.critical(message, exc_info=exception)
        else:
            self.log_with_context(logging.CRITICAL, message, **context)


class RequestContextLogger:
    """Log request processing with context"""

    def __init__(self, logger: StructuredLogger):
        self.logger = logger

    def log_request_start(self, method: str, path: str,
                         client_ip: str = "unknown") -> None:
        """Log start of request handling"""
        self.logger.info(
            "Request started",
            method=method,
            path=path,
            client_ip=client_ip
        )

    def log_request_end(self, method: str, path: str, status_code: int,
                       duration_ms: float) -> None:
        """Log end of request handling"""
        level = logging.WARNING if status_code >= 400 else logging.INFO
        self.logger.log_with_context(
            level,
            "Request completed",
            method=method,
            path=path,
            status_code=status_code,
            duration_ms=duration_ms
        )

    def log_error(self, message: str, exception: Optional[Exception] = None,
                  context: Optional[Dict[str, Any]] = None) -> None:
        """Log request error"""
        self.logger.error(message, exception=exception, **(context or {}))


def configure_logging(app_name: str, log_dir: Optional[str] = None,
                     level: int = logging.INFO) -> StructuredLogger:
    """
    Configure application logging.
    
    Args:
        app_name: Application name
        log_dir: Directory for log files
        level: Logging level
    
    Returns:
        StructuredLogger instance
    """
    log_file = None
    if log_dir:
        log_file = str(Path(log_dir) / f"{app_name}.log")

    return StructuredLogger(app_name, log_file, level)
