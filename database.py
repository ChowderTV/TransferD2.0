#!/usr/bin/env python3
"""
Database module for TransferD Web - SQLite persistence layer
"""

import sqlite3
import json
import time
from pathlib import Path
from contextlib import contextmanager
from typing import List, Dict, Optional, Tuple


class TransferDatabase:
    def __init__(self, db_path: str = '/app/data/transferd.db'):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        try:
            yield conn
        finally:
            conn.close()
    
    def init_database(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            # Devices table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_port TEXT UNIQUE NOT NULL,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_manual BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Messages table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content TEXT NOT NULL,
                    sender_ip TEXT NOT NULL,
                    recipient_ip TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    message_type TEXT DEFAULT 'text'
                )
            ''')
            
            # Transfer history table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS transfer_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    file_size INTEGER,
                    sender_ip TEXT NOT NULL,
                    recipient_ip TEXT,
                    transfer_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    error_message TEXT
                )
            ''')
            
            # Settings table for app configuration
            conn.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
    
    # Device management
    def add_device(self, ip_port: str, is_manual: bool = False) -> bool:
        """Add a device to the database"""
        try:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO devices (ip_port, is_manual, last_seen)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                ''', (ip_port, is_manual))
                conn.commit()
                return True
        except sqlite3.Error:
            return False
    
    def get_devices(self) -> List[Dict]:
        """Get all devices from database"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT ip_port, discovered_at, last_seen, is_manual
                FROM devices
                ORDER BY last_seen DESC
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    def get_device_list(self) -> List[str]:
        """Get simple list of device IP:port strings"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT ip_port FROM devices ORDER BY last_seen DESC')
            return [row['ip_port'] for row in cursor.fetchall()]
    
    def update_device_last_seen(self, ip_port: str):
        """Update last seen timestamp for a device"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE devices SET last_seen = CURRENT_TIMESTAMP
                WHERE ip_port = ?
            ''', (ip_port,))
            conn.commit()
    
    def remove_device(self, ip_port: str) -> bool:
        """Remove a device from database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.execute('DELETE FROM devices WHERE ip_port = ?', (ip_port,))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error:
            return False
    
    # Message management
    def add_message(self, content: str, sender_ip: str, recipient_ip: str = None, 
                   message_type: str = 'text') -> bool:
        """Add a message to the database"""
        try:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT INTO messages (content, sender_ip, recipient_ip, message_type)
                    VALUES (?, ?, ?, ?)
                ''', (content, sender_ip, recipient_ip, message_type))
                conn.commit()
                return True
        except sqlite3.Error:
            return False
    
    def get_recent_messages(self, limit: int = 50) -> List[Dict]:
        """Get recent messages from database"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT content, sender_ip, recipient_ip, timestamp, message_type
                FROM messages
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            messages = [dict(row) for row in cursor.fetchall()]
            # Reverse to get chronological order
            return list(reversed(messages))
    
    def get_message_history(self, sender_ip: str = None, recipient_ip: str = None, 
                           limit: int = 100) -> List[Dict]:
        """Get message history with optional filtering"""
        query = '''
            SELECT content, sender_ip, recipient_ip, timestamp, message_type
            FROM messages
        '''
        params = []
        conditions = []
        
        if sender_ip:
            conditions.append('sender_ip = ?')
            params.append(sender_ip)
        
        if recipient_ip:
            conditions.append('recipient_ip = ?')
            params.append(recipient_ip)
        
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def cleanup_old_messages(self, days: int = 30):
        """Clean up messages older than specified days"""
        with self.get_connection() as conn:
            conn.execute('''
                DELETE FROM messages
                WHERE timestamp < datetime('now', '-{} days')
            '''.format(days))
            conn.commit()
    
    # Transfer history management
    def add_transfer(self, filename: str, file_size: int, sender_ip: str, 
                    recipient_ip: str = None, transfer_type: str = 'upload', 
                    status: str = 'completed', error_message: str = None) -> bool:
        """Add a transfer record to the database"""
        try:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT INTO transfer_history 
                    (filename, file_size, sender_ip, recipient_ip, transfer_type, status, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (filename, file_size, sender_ip, recipient_ip, transfer_type, status, error_message))
                conn.commit()
                return True
        except sqlite3.Error:
            return False
    
    def get_transfer_history(self, limit: int = 50) -> List[Dict]:
        """Get recent transfer history"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT filename, file_size, sender_ip, recipient_ip, 
                       transfer_type, status, timestamp, error_message
                FROM transfer_history
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def cleanup_old_transfers(self, days: int = 90):
        """Clean up transfer history older than specified days"""
        with self.get_connection() as conn:
            conn.execute('''
                DELETE FROM transfer_history
                WHERE timestamp < datetime('now', '-{} days')
            '''.format(days))
            conn.commit()
    
    # Settings management
    def set_setting(self, key: str, value: str) -> bool:
        """Set a configuration setting"""
        try:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO settings (key, value, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                ''', (key, value))
                conn.commit()
                return True
        except sqlite3.Error:
            return False
    
    def get_setting(self, key: str, default: str = None) -> Optional[str]:
        """Get a configuration setting"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT value FROM settings WHERE key = ?', (key,))
            row = cursor.fetchone()
            return row['value'] if row else default
    
    def get_all_settings(self) -> Dict[str, str]:
        """Get all configuration settings"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT key, value FROM settings')
            return {row['key']: row['value'] for row in cursor.fetchall()}
    
    # Database maintenance
    def vacuum(self):
        """Optimize database"""
        with self.get_connection() as conn:
            conn.execute('VACUUM')
    
    def get_database_info(self) -> Dict:
        """Get database statistics"""
        with self.get_connection() as conn:
            stats = {}
            
            # Get table counts
            tables = ['devices', 'messages', 'transfer_history', 'settings']
            for table in tables:
                cursor = conn.execute(f'SELECT COUNT(*) as count FROM {table}')
                stats[f'{table}_count'] = cursor.fetchone()['count']
            
            # Get database size
            stats['db_size'] = self.db_path.stat().st_size if self.db_path.exists() else 0
            
            return stats