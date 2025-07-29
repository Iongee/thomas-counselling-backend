import json
import time
import threading
from typing import Dict, Set, Any, Optional
from django.utils import timezone
from django.contrib.auth import get_user_model
import logging

User = get_user_model()
logger = logging.getLogger(__name__)

class SSEConnection:
    def __init__(self, user_id: int, event_queue):
        self.user_id = user_id
        self.event_queue = event_queue
        self.is_active = True
        self.last_ping = timezone.now()
    
    def send_event(self, event_type: str, data: Dict[str, Any]):
        """Send an event to this connection"""
        if not self.is_active:
            return False
        
        try:
            event_data = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
            self.event_queue.append(event_data)
            return True
        except Exception as e:
            logger.error(f"Error sending event to user {self.user_id}: {e}")
            self.is_active = False
            return False
    
    def ping(self):
        """Send a heartbeat to keep connection alive"""
        self.last_ping = timezone.now()
        return self.send_event('heartbeat', {
            'timestamp': timezone.now().isoformat()
        })

class SSEConnectionManager:
    def __init__(self):
        self.connections: Dict[int, SSEConnection] = {}
        self.lock = threading.Lock()
    
    def add_connection(self, user_id: int, event_queue):
        """Add a new SSE connection"""
        with self.lock:
            # Close existing connection if any
            if user_id in self.connections:
                self.connections[user_id].is_active = False
            
            connection = SSEConnection(user_id, event_queue)
            self.connections[user_id] = connection
            logger.info(f"SSE connection added for user {user_id}")
            return connection
    
    def remove_connection(self, user_id: int):
        """Remove an SSE connection"""
        with self.lock:
            if user_id in self.connections:
                self.connections[user_id].is_active = False
                del self.connections[user_id]
                logger.info(f"SSE connection removed for user {user_id}")
    
    def broadcast_to_user(self, user_id: int, event_type: str, data: Dict[str, Any]):
        """Broadcast an event to a specific user"""
        with self.lock:
            print(f"SSE Manager: Active connections: {list(self.connections.keys())}")
            print(f"SSE Manager: Attempting to send {event_type} to user {user_id}")
            if user_id in self.connections:
                connection = self.connections[user_id]
                print(f"SSE Manager: Found connection for user {user_id}, connection active: {connection.is_active}")
                print(f"SSE Manager: Event queue length before send: {len(connection.event_queue)}")
                success = connection.send_event(event_type, data)
                print(f"SSE Manager: Event queue length after send: {len(connection.event_queue)}")
                print(f"SSE Manager: Send success: {success}")
                if not success:
                    logger.warning(f"Failed to send event to user {user_id}, removing connection")
                    self.remove_connection(user_id)
                return success
            else:
                print(f"SSE Manager: No SSE connection found for user {user_id}")
        return False
    
    def broadcast_to_users(self, user_ids: Set[int], event_type: str, data: Dict[str, Any]):
        """Broadcast an event to multiple users"""
        results = {}
        for user_id in user_ids:
            results[user_id] = self.broadcast_to_user(user_id, event_type, data)
        return results
    
    def get_active_connections(self) -> Dict[int, SSEConnection]:
        """Get all active connections"""
        with self.lock:
            return {uid: conn for uid, conn in self.connections.items() if conn.is_active}
    
    def cleanup_stale_connections(self, max_age_minutes: int = 30):
        """Remove connections that haven't been active recently"""
        cutoff_time = timezone.now() - timezone.timedelta(minutes=max_age_minutes)
        stale_connections = []
        
        with self.lock:
            for user_id, connection in self.connections.items():
                if connection.last_ping < cutoff_time:
                    stale_connections.append(user_id)
        
        for user_id in stale_connections:
            self.remove_connection(user_id)
        
        if stale_connections:
            logger.info(f"Cleaned up {len(stale_connections)} stale SSE connections")

# Global SSE connection manager
sse_manager = SSEConnectionManager() 