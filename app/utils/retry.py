"""
Retry logic for feed updates and API calls
"""

import asyncio
import time
from typing import TypeVar, Callable, Optional, Any
from functools import wraps
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


class RetryConfig:
    """Configuration for retry behavior"""

    def __init__(self, max_retries: int = 3, base_delay: float = 1.0,
                 max_delay: float = 60.0, exponential_base: float = 2.0,
                 jitter: bool = True):
        """
        Initialize retry configuration.
        
        Args:
            max_retries: Maximum number of retry attempts
            base_delay: Initial delay in seconds
            max_delay: Maximum delay in seconds
            exponential_base: Base for exponential backoff
            jitter: Whether to add random jitter to delays
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter

    def get_delay(self, attempt: int) -> float:
        """
        Calculate delay for attempt number.
        
        Args:
            attempt: Attempt number (0-indexed)
        
        Returns:
            Delay in seconds
        """
        delay = self.base_delay * (self.exponential_base ** attempt)
        delay = min(delay, self.max_delay)

        if self.jitter:
            import random
            delay = delay * (0.5 + random.random())

        return delay


def retry_on_exception(config: Optional[RetryConfig] = None,
                      exceptions: tuple = (Exception,),
                      on_retry: Optional[Callable] = None):
    """
    Decorator for synchronous functions with retry logic.
    
    Args:
        config: RetryConfig instance
        exceptions: Tuple of exceptions to catch
        on_retry: Callback function called on each retry
    """
    if config is None:
        config = RetryConfig()

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None

            for attempt in range(config.max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < config.max_retries:
                        delay = config.get_delay(attempt)
                        logger.warning(
                            f"Attempt {attempt + 1} failed for {func.__name__}: {e}. "
                            f"Retrying in {delay:.2f}s..."
                        )
                        if on_retry:
                            on_retry(attempt, delay, e)
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"All {config.max_retries + 1} attempts failed for {func.__name__}"
                        )

            raise last_exception

        return wrapper

    return decorator


def async_retry_on_exception(config: Optional[RetryConfig] = None,
                            exceptions: tuple = (Exception,),
                            on_retry: Optional[Callable] = None):
    """
    Decorator for async functions with retry logic.
    
    Args:
        config: RetryConfig instance
        exceptions: Tuple of exceptions to catch
        on_retry: Callback function called on each retry
    """
    if config is None:
        config = RetryConfig()

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            last_exception = None

            for attempt in range(config.max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < config.max_retries:
                        delay = config.get_delay(attempt)
                        logger.warning(
                            f"Attempt {attempt + 1} failed for {func.__name__}: {e}. "
                            f"Retrying in {delay:.2f}s..."
                        )
                        if on_retry:
                            on_retry(attempt, delay, e)
                        await asyncio.sleep(delay)
                    else:
                        logger.error(
                            f"All {config.max_retries + 1} attempts failed for {func.__name__}"
                        )

            raise last_exception

        return wrapper

    return decorator


class SimpleRetry:
    """Simple retry helper without decorators"""

    @staticmethod
    def execute(func: Callable[..., T], config: Optional[RetryConfig] = None,
               exceptions: tuple = (Exception,), **kwargs) -> T:
        """
        Execute function with retry logic.
        
        Args:
            func: Function to execute
            config: RetryConfig instance
            exceptions: Tuple of exceptions to catch
            **kwargs: Arguments to pass to function
        
        Returns:
            Function result
        """
        if config is None:
            config = RetryConfig()

        last_exception = None

        for attempt in range(config.max_retries + 1):
            try:
                return func(**kwargs)
            except exceptions as e:
                last_exception = e
                if attempt < config.max_retries:
                    delay = config.get_delay(attempt)
                    logger.warning(
                        f"Attempt {attempt + 1} failed: {e}. "
                        f"Retrying in {delay:.2f}s..."
                    )
                    time.sleep(delay)

        raise last_exception

    @staticmethod
    async def execute_async(func: Callable[..., Any], 
                           config: Optional[RetryConfig] = None,
                           exceptions: tuple = (Exception,), **kwargs) -> Any:
        """
        Execute async function with retry logic.
        
        Args:
            func: Async function to execute
            config: RetryConfig instance
            exceptions: Tuple of exceptions to catch
            **kwargs: Arguments to pass to function
        
        Returns:
            Function result
        """
        if config is None:
            config = RetryConfig()

        last_exception = None

        for attempt in range(config.max_retries + 1):
            try:
                return await func(**kwargs)
            except exceptions as e:
                last_exception = e
                if attempt < config.max_retries:
                    delay = config.get_delay(attempt)
                    logger.warning(
                        f"Attempt {attempt + 1} failed: {e}. "
                        f"Retrying in {delay:.2f}s..."
                    )
                    await asyncio.sleep(delay)

        raise last_exception
