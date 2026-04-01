"""
Feed Scheduler with Midnight UTC Daily Refresh
Manages scheduled updates for threat intelligence feeds
Supports immediate polls, interval-based updates, and midnight UTC synchronization
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class FeedPriority(Enum):
    """Feed priority levels for refresh scheduling"""
    CRITICAL = 1      # Real-time feeds (DShield, GrayNoise)
    HIGH = 2          # Critical intel (vulnerabilities, exposures)
    MEDIUM = 3        # Standard intel (reputation lists, domains)
    LOW = 4           # Background feeds (news, trends)


@dataclass
class FeedSchedule:
    """Feed scheduling configuration"""
    feed_id: str
    feed_name: str
    update_interval: int = 3600  # seconds (default 1 hour)
    priority: FeedPriority = FeedPriority.MEDIUM
    last_update: Optional[datetime] = None
    next_update: Optional[datetime] = None
    enabled: bool = True
    refresh_at_midnight_utc: bool = False  # Force refresh at midnight UTC
    max_retries: int = 3
    retry_backoff: int = 300  # seconds
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "feed_id": self.feed_id,
            "feed_name": self.feed_name,
            "update_interval": self.update_interval,
            "priority": self.priority.name,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "next_update": self.next_update.isoformat() if self.next_update else None,
            "enabled": self.enabled,
            "refresh_at_midnight_utc": self.refresh_at_midnight_utc,
            "max_retries": self.max_retries,
            "last_error": self.last_error,
            "consecutive_failures": self.consecutive_failures,
        }


class FeedScheduler:
    """
    Centralized scheduler for feed updates
    Manages multiple feeds with different schedules and priorities
    Provides midnight UTC synchronization across feeds
    """

    def __init__(self, state_file: Optional[str] = None):
        self.feeds: Dict[str, FeedSchedule] = {}
        self.feed_callbacks: Dict[str, Callable] = {}
        self.is_running = False
        self.update_lock = asyncio.Lock()
        self.state_file = state_file or "data/feed_schedule_state.json"
        self._load_state()

    def register_feed(
        self,
        feed_id: str,
        feed_name: str,
        callback: Callable,
        update_interval: int = 3600,
        priority: FeedPriority = FeedPriority.MEDIUM,
        refresh_at_midnight_utc: bool = False,
    ) -> FeedSchedule:
        """
        Register a new feed with the scheduler
        
        Args:
            feed_id: Unique identifier for the feed
            feed_name: Human-readable name
            callback: Async function to call for feed update
            update_interval: Seconds between updates
            priority: Priority level for scheduling
            refresh_at_midnight_utc: Force refresh at midnight UTC daily
        
        Returns:
            FeedSchedule object
        """
        schedule = FeedSchedule(
            feed_id=feed_id,
            feed_name=feed_name,
            update_interval=update_interval,
            priority=priority,
            refresh_at_midnight_utc=refresh_at_midnight_utc,
        )
        self.feeds[feed_id] = schedule
        self.feed_callbacks[feed_id] = callback
        logger.info(f"Registered feed: {feed_name} (interval: {update_interval}s, priority: {priority.name})")
        return schedule

    def unregister_feed(self, feed_id: str) -> bool:
        """Unregister a feed from the scheduler"""
        if feed_id in self.feeds:
            del self.feeds[feed_id]
            del self.feed_callbacks[feed_id]
            logger.info(f"Unregistered feed: {feed_id}")
            return True
        return False

    def enable_feed(self, feed_id: str) -> bool:
        """Enable a feed"""
        if feed_id in self.feeds:
            self.feeds[feed_id].enabled = True
            logger.info(f"Enabled feed: {feed_id}")
            return True
        return False

    def disable_feed(self, feed_id: str) -> bool:
        """Disable a feed"""
        if feed_id in self.feeds:
            self.feeds[feed_id].enabled = False
            logger.info(f"Disabled feed: {feed_id}")
            return True
        return False

    def get_feed_status(self, feed_id: Optional[str] = None) -> Dict[str, Any]:
        """Get status of one or all feeds"""
        if feed_id:
            if feed_id not in self.feeds:
                return {}
            return self.feeds[feed_id].to_dict()
        
        return {fid: schedule.to_dict() for fid, schedule in self.feeds.items()}

    def _calculate_next_update(self, feed: FeedSchedule) -> datetime:
        """Calculate when the feed should next be updated"""
        now = datetime.now(timezone.utc)
        
        if feed.refresh_at_midnight_utc:
            # Calculate midnight UTC today or tomorrow
            midnight = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            # If current time is before midnight, use today's midnight
            if now.time() < midnight.time():
                midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
            return midnight
        
        # Standard interval-based update
        if feed.last_update:
            return feed.last_update + timedelta(seconds=feed.update_interval)
        else:
            # First update: immediate or after backoff if failures
            if feed.consecutive_failures > 0:
                backoff = feed.retry_backoff * (2 ** (feed.consecutive_failures - 1))
                return now + timedelta(seconds=backoff)
            return now

    def _should_update_now(self, feed: FeedSchedule) -> bool:
        """Check if a feed should be updated now"""
        if not feed.enabled:
            return False
        
        now = datetime.now(timezone.utc)
        if feed.next_update is None or now >= feed.next_update:
            return True
        
        return False

    async def update_feed(
        self,
        feed_id: str,
        force: bool = False,
    ) -> tuple[bool, Optional[str]]:
        """
        Update a specific feed
        
        Args:
            feed_id: Feed to update
            force: Skip schedule check and update immediately
        
        Returns:
            (success, error_message)
        """
        if feed_id not in self.feeds:
            return False, f"Feed {feed_id} not found"
        
        feed = self.feeds[feed_id]

        if not force and not self._should_update_now(feed):
            return False, "Update not yet due"

        async with self.update_lock:
            try:
                logger.info(f"Updating feed: {feed.feed_name}")
                callback = self.feed_callbacks[feed_id]
                
                # Call the feed update callback
                await callback() if asyncio.iscoroutinefunction(callback) else callback()
                
                # Update schedule state
                now = datetime.now(timezone.utc)
                feed.last_update = now
                feed.next_update = self._calculate_next_update(feed)
                feed.last_error = None
                feed.consecutive_failures = 0
                
                logger.info(
                    f"Feed {feed.feed_name} updated successfully. "
                    f"Next update: {feed.next_update}"
                )
                self._save_state()
                return True, None

            except Exception as e:
                feed.consecutive_failures += 1
                feed.last_error = str(e)
                feed.next_update = self._calculate_next_update(feed)
                
                logger.error(
                    f"Feed {feed.feed_name} update failed "
                    f"(attempt {feed.consecutive_failures}/{feed.max_retries}): {e}"
                )
                self._save_state()
                
                if feed.consecutive_failures >= feed.max_retries:
                    logger.warning(f"Feed {feed.feed_name} exceeded max retries, will retry at next interval")
                
                return False, str(e)

    async def update_all_feeds(self, force_all: bool = False) -> Dict[str, tuple[bool, Optional[str]]]:
        """
        Update all due feeds
        
        Args:
            force_all: Update all enabled feeds immediately
        
        Returns:
            Dictionary mapping feed_id to (success, error_message)
        """
        results = {}
        
        # Sort feeds by priority for update order
        sorted_feeds = sorted(
            self.feeds.items(),
            key=lambda x: x[1].priority.value
        )
        
        for feed_id, feed in sorted_feeds:
            success, error = await self.update_feed(feed_id, force=force_all)
            results[feed_id] = (success, error)
        
        return results

    async def start_scheduler(self, check_interval: int = 60):
        """
        Start the background scheduler
        
        Args:
            check_interval: Seconds between schedule checks
        """
        self.is_running = True
        logger.info(f"Feed scheduler started (check interval: {check_interval}s)")
        
        try:
            while self.is_running:
                # Check which feeds need updates
                due_feeds = []
                for feed_id, feed in self.feeds.items():
                    if self._should_update_now(feed):
                        due_feeds.append(feed_id)
                
                # Update due feeds
                if due_feeds:
                    logger.debug(f"Updating {len(due_feeds)} feeds due for refresh")
                    for feed_id in due_feeds:
                        await self.update_feed(feed_id)
                
                # Wait before next check
                await asyncio.sleep(check_interval)
        
        except asyncio.CancelledError:
            logger.info("Feed scheduler stopped")
            self.is_running = False
        except Exception as e:
            logger.error(f"Feed scheduler error: {e}")
            self.is_running = False

    def stop_scheduler(self):
        """Stop the background scheduler"""
        self.is_running = False
        logger.info("Feed scheduler stop requested")

    def _save_state(self):
        """Persist feed schedule state to file"""
        try:
            Path(self.state_file).parent.mkdir(parents=True, exist_ok=True)
            state = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "feeds": {fid: schedule.to_dict() for fid, schedule in self.feeds.items()}
            }
            with open(self.state_file, "w") as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save scheduler state: {e}")

    def _load_state(self):
        """Load feed schedule state from file"""
        try:
            if not Path(self.state_file).exists():
                return
            
            with open(self.state_file, "r") as f:
                state = json.load(f)
            
            # Restore schedule states (optional - mainly for last_update tracking)
            logger.info("Scheduler state loaded from file")
        except Exception as e:
            logger.warning(f"Failed to load scheduler state: {e}")

    def get_next_midnight_utc(self) -> datetime:
        """Get the next midnight UTC time"""
        now = datetime.now(timezone.utc)
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        if now >= midnight:
            midnight += timedelta(days=1)
        return midnight

    def get_feeds_by_priority(self, priority: FeedPriority) -> List[str]:
        """Get list of feed IDs with a specific priority"""
        return [
            fid for fid, schedule in self.feeds.items()
            if schedule.priority == priority and schedule.enabled
        ]
