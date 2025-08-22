#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================
  BOSS檢測器 Railway Flask 應用 (PostgreSQL版)
===========================================
作者: @yyv3vnn (Telegram)
功能: Railway 部署的 Flask API 伺服器 (支援 PostgreSQL)
版本: 5.2.0 (修復增強版)
更新: 2025-08-22
===========================================
"""

import os
import datetime
import pytz
import sys
import json
import hashlib
import sqlite3
import logging
import uuid
import secrets

# 在導入其他模組前，先檢查和設置環境變量
print(f"🔍 DATABASE_URL 環境變量: {bool(os.environ.get('DATABASE_URL'))}")
database_url = os.environ.get('DATABASE_URL')
if database_url:
    print(f"✅ 找到 DATABASE_URL: {database_url[:50]}...")
else:
    print("❌ 未找到 DATABASE_URL 環境變量")

# 嘗試導入 psycopg2
PSYCOPG2_AVAILABLE = False
try:
    import psycopg2
    import psycopg2.extras
    print("✅ psycopg2 導入成功")
    PSYCOPG2_AVAILABLE = True
except ImportError as e:
    print(f"❌ psycopg2 導入失敗: {e}")
    print("🔄 將使用 SQLite 作為回退")
    PSYCOPG2_AVAILABLE = False
except Exception as e:
    print(f"❌ psycopg2 未知錯誤: {e}")
    PSYCOPG2_AVAILABLE = False

from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

# 設置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

os.environ['TZ'] = 'Asia/Taipei'

# 創建 Flask 應用實例
app = Flask(__name__)
CORS(app)

# 配置
app.config['SECRET_KEY'] = 'boss_detector_2025_secret_key'
app.config['JSON_AS_ASCII'] = False

class DatabaseManager:
    """資料庫管理器 - 支援 PostgreSQL 和 SQLite"""
    
    def __init__(self):
        self.admin_key = "boss_admin_2025_enhanced_key_v6"
        self.master_key = "boss_detector_2025_enhanced_aes_master_key_v6"
        self.database_url = os.environ.get('DATABASE_URL')
        
        # 驗證令牌管理
        self.active_tokens = {}  # 存儲活躍的驗證令牌
        self.token_expiry_hours = 24  # 令牌過期時間（小時）
        
        print(f"🔍 初始化資料庫管理器...")
        print(f"   DATABASE_URL 存在: {bool(self.database_url)}")
        print(f"   psycopg2 可用: {PSYCOPG2_AVAILABLE}")
        
        # 決定使用哪種資料庫
        if self.database_url and PSYCOPG2_AVAILABLE:
            print("🧪 測試 PostgreSQL 連接...")
            try:
                # 測試連接
                test_conn = psycopg2.connect(self.database_url)
                test_conn.close()
                print("✅ PostgreSQL 連接測試成功")
                
                self.use_postgresql = True
                logger.info("🐘 使用 PostgreSQL 資料庫")
                self.init_postgresql()
            except Exception as e:
                print(f"❌ PostgreSQL 連接失敗: {e}")
                print("🔄 回退到 SQLite")
                self.use_postgresql = False
                self.db_path = "boss_detector.db"
                logger.info("🗄️ 使用 SQLite 資料庫 (PostgreSQL 連接失敗)")
                self.init_sqlite()
        else:
            # 回退到 SQLite
            self.use_postgresql = False
            self.db_path = "boss_detector.db"
            if not self.database_url:
                logger.info("🗄️ 使用 SQLite 資料庫 (未找到 DATABASE_URL)")
                print("📝 原因: 未找到 DATABASE_URL 環境變量")
            elif not PSYCOPG2_AVAILABLE:
                logger.info("🗄️ 使用 SQLite 資料庫 (psycopg2 不可用)")
                print("📝 原因: psycopg2 庫不可用")
            self.init_sqlite()
    
    def get_connection(self):
        """獲取資料庫連接"""
        if self.use_postgresql:
            return psycopg2.connect(self.database_url)
        else:
            return sqlite3.connect(self.db_path)
    
    def init_postgresql(self):
        """初始化 PostgreSQL 資料庫"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            print("🔧 創建 PostgreSQL 表...")
            
            # 序號表 (增強版)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS serials (
                    id SERIAL PRIMARY KEY,
                    serial_key TEXT UNIQUE NOT NULL,
                    serial_hash TEXT UNIQUE NOT NULL,
                    machine_id TEXT NOT NULL,
                    user_name TEXT DEFAULT '使用者',
                    tier TEXT DEFAULT 'trial',
                    created_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expiry_date TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    last_check_time TIMESTAMP,
                    check_count INTEGER DEFAULT 0,
                    revoked_date TIMESTAMP,
                    revoked_reason TEXT,
                    created_by TEXT DEFAULT 'api',
                    encryption_type TEXT DEFAULT 'AES+XOR',
                    force_online BOOLEAN DEFAULT FALSE,
                    validation_required BOOLEAN DEFAULT TRUE,
                    offline_disabled BOOLEAN DEFAULT FALSE,
                    server_validation_only BOOLEAN DEFAULT FALSE,
                    version TEXT DEFAULT '6.0.0',
                    generator TEXT DEFAULT '@yyv3vnn',
                    client_ip TEXT,
                    user_agent TEXT,
                    last_validation_ip TEXT,
                    validation_count INTEGER DEFAULT 0,
                    notes TEXT,
                    metadata JSONB
                )
            ''')
            
            # 黑名單表 (增強版)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blacklist (
                    id SERIAL PRIMARY KEY,
                    machine_id TEXT UNIQUE NOT NULL,
                    reason TEXT DEFAULT '違規使用',
                    created_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_by TEXT DEFAULT 'admin',
                    is_active BOOLEAN DEFAULT TRUE,
                    expires_at TIMESTAMP,
                    severity TEXT DEFAULT 'medium',
                    notes TEXT,
                    metadata JSONB
                )
            ''')
            
            # 驗證日誌表 (增強版)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS validation_logs (
                    id SERIAL PRIMARY KEY,
                    serial_hash TEXT NOT NULL,
                    machine_id TEXT NOT NULL,
                    validation_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    result TEXT NOT NULL,
                    client_ip TEXT,
                    user_agent TEXT,
                    validation_method TEXT DEFAULT 'force_online',
                    server_response_time INTEGER,
                    error_message TEXT,
                    metadata JSONB
                )
            ''')
            
            # 驗證令牌表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS validation_tokens (
                    id SERIAL PRIMARY KEY,
                    token_id TEXT UNIQUE NOT NULL,
                    token_hash TEXT UNIQUE NOT NULL,
                    created_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_by TEXT DEFAULT 'api',
                    usage_count INTEGER DEFAULT 0,
                    last_used_at TIMESTAMP,
                    client_ip TEXT,
                    metadata JSONB
                )
            ''')
            
            # 管理操作日誌表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admin_logs (
                    id SERIAL PRIMARY KEY,
                    action_type TEXT NOT NULL,
                    action_description TEXT,
                    performed_by TEXT DEFAULT 'admin',
                    performed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    target_serial_hash TEXT,
                    target_machine_id TEXT,
                    client_ip TEXT,
                    success BOOLEAN DEFAULT TRUE,
                    error_message TEXT,
                    metadata JSONB
                )
            ''')
            
            # 系統統計表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_stats (
                    id SERIAL PRIMARY KEY,
                    stat_date DATE NOT NULL DEFAULT CURRENT_DATE,
                    total_serials INTEGER DEFAULT 0,
                    active_serials INTEGER DEFAULT 0,
                    total_validations INTEGER DEFAULT 0,
                    successful_validations INTEGER DEFAULT 0,
                    failed_validations INTEGER DEFAULT 0,
                    blacklist_count INTEGER DEFAULT 0,
                    force_online_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(stat_date)
                )
            ''')
            
            # 創建索引
            indexes = [
                'CREATE INDEX IF NOT EXISTS idx_serial_hash ON serials(serial_hash)',
                'CREATE INDEX IF NOT EXISTS idx_machine_id ON serials(machine_id)',
                'CREATE INDEX IF NOT EXISTS idx_serial_key ON serials(serial_key)',
                'CREATE INDEX IF NOT EXISTS idx_serial_active ON serials(is_active)',
                'CREATE INDEX IF NOT EXISTS idx_serial_expiry ON serials(expiry_date)',
                'CREATE INDEX IF NOT EXISTS idx_serial_force_online ON serials(force_online)',
                'CREATE INDEX IF NOT EXISTS idx_validation_time ON validation_logs(validation_time)',
                'CREATE INDEX IF NOT EXISTS idx_validation_result ON validation_logs(result)',
                'CREATE INDEX IF NOT EXISTS idx_blacklist_machine ON blacklist(machine_id)',
                'CREATE INDEX IF NOT EXISTS idx_blacklist_active ON blacklist(is_active)',
                'CREATE INDEX IF NOT EXISTS idx_tokens_active ON validation_tokens(is_active)',
                'CREATE INDEX IF NOT EXISTS idx_tokens_expires ON validation_tokens(expires_at)',
                'CREATE INDEX IF NOT EXISTS idx_admin_logs_time ON admin_logs(performed_at)',
                'CREATE INDEX IF NOT EXISTS idx_stats_date ON system_stats(stat_date)'
            ]
            
            for index_sql in indexes:
                cursor.execute(index_sql)
            
            conn.commit()
            conn.close()
            print("✅ PostgreSQL 表創建完成")
            logger.info("✅ PostgreSQL 資料庫初始化成功")
            
        except Exception as e:
            print(f"❌ PostgreSQL 初始化失敗: {e}")
            logger.error(f"❌ PostgreSQL 初始化失敗: {e}")
            raise
    
    def init_sqlite(self):
        """初始化 SQLite 資料庫（回退方案）"""
        try:
            print("🔧 創建 SQLite 資料庫...")
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 序號表 (SQLite版本)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS serials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial_key TEXT UNIQUE NOT NULL,
                    serial_hash TEXT UNIQUE NOT NULL,
                    machine_id TEXT NOT NULL,
                    user_name TEXT DEFAULT '使用者',
                    tier TEXT DEFAULT 'trial',
                    created_date TEXT NOT NULL,
                    expiry_date TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    last_check_time TEXT,
                    check_count INTEGER DEFAULT 0,
                    revoked_date TEXT,
                    revoked_reason TEXT,
                    created_by TEXT DEFAULT 'api',
                    encryption_type TEXT DEFAULT 'AES+XOR',
                    force_online BOOLEAN DEFAULT 0,
                    validation_required BOOLEAN DEFAULT 1,
                    offline_disabled BOOLEAN DEFAULT 0,
                    server_validation_only BOOLEAN DEFAULT 0,
                    version TEXT DEFAULT '6.0.0',
                    generator TEXT DEFAULT '@yyv3vnn',
                    client_ip TEXT,
                    user_agent TEXT,
                    last_validation_ip TEXT,
                    validation_count INTEGER DEFAULT 0,
                    notes TEXT,
                    metadata TEXT
                )
            ''')
            
            # 其他表的SQLite版本...
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    machine_id TEXT UNIQUE NOT NULL,
                    reason TEXT DEFAULT '違規使用',
                    created_date TEXT NOT NULL,
                    created_by TEXT DEFAULT 'admin',
                    is_active BOOLEAN DEFAULT 1,
                    expires_at TEXT,
                    severity TEXT DEFAULT 'medium',
                    notes TEXT,
                    metadata TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS validation_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial_hash TEXT NOT NULL,
                    machine_id TEXT NOT NULL,
                    validation_time TEXT NOT NULL,
                    result TEXT NOT NULL,
                    client_ip TEXT,
                    user_agent TEXT,
                    validation_method TEXT DEFAULT 'force_online',
                    server_response_time INTEGER,
                    error_message TEXT,
                    metadata TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS validation_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id TEXT UNIQUE NOT NULL,
                    token_hash TEXT UNIQUE NOT NULL,
                    created_date TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_by TEXT DEFAULT 'api',
                    usage_count INTEGER DEFAULT 0,
                    last_used_at TEXT,
                    client_ip TEXT,
                    metadata TEXT
                )
            ''')
            
            # 創建索引
            indexes = [
                'CREATE INDEX IF NOT EXISTS idx_serial_hash ON serials(serial_hash)',
                'CREATE INDEX IF NOT EXISTS idx_machine_id ON serials(machine_id)',
                'CREATE INDEX IF NOT EXISTS idx_serial_key ON serials(serial_key)',
                'CREATE INDEX IF NOT EXISTS idx_validation_time ON validation_logs(validation_time)',
                'CREATE INDEX IF NOT EXISTS idx_blacklist_machine ON blacklist(machine_id)',
                'CREATE INDEX IF NOT EXISTS idx_tokens_active ON validation_tokens(is_active)'
            ]
            
            for index_sql in indexes:
                cursor.execute(index_sql)
            
            conn.commit()
            conn.close()
            print("✅ SQLite 資料庫創建完成")
            logger.info("✅ SQLite 資料庫初始化成功")
            
        except Exception as e:
            print(f"❌ SQLite 初始化失敗: {e}")
            logger.error(f"❌ SQLite 初始化失敗: {e}")
            raise
    
    def generate_validation_token(self) -> Dict[str, Any]:
        """生成驗證令牌"""
        try:
            token_id = str(uuid.uuid4())
            token_hash = hashlib.sha256(f"{token_id}{self.master_key}{datetime.now()}".encode()).hexdigest()
            created_date = datetime.now()
            expires_at = created_date + timedelta(hours=self.token_expiry_hours)
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    INSERT INTO validation_tokens 
                    (token_id, token_hash, created_date, expires_at, is_active, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (token_id, token_hash, created_date, expires_at, True, 'api'))
            else:
                cursor.execute('''
                    INSERT INTO validation_tokens 
                    (token_id, token_hash, created_date, expires_at, is_active, created_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (token_id, token_hash, self._format_datetime(created_date), 
                      self._format_datetime(expires_at), 1, 'api'))
            
            conn.commit()
            conn.close()
            
            # 存儲到內存中
            self.active_tokens[token_hash] = {
                'token_id': token_id,
                'created_at': created_date,
                'expires_at': expires_at
            }
            
            return {
                'success': True,
                'token': token_hash,
                'expires_at': expires_at.isoformat(),
                'expires_in_hours': self.token_expiry_hours
            }
            
        except Exception as e:
            logger.error(f"❌ 生成驗證令牌失敗: {e}")
            return {'success': False, 'error': str(e)}
    
    def validate_token(self, token: str) -> bool:
        """驗證令牌有效性"""
        try:
            # 首先檢查內存中的令牌
            if token in self.active_tokens:
                token_info = self.active_tokens[token]
                if datetime.now() < token_info['expires_at']:
                    return True
                else:
                    # 令牌過期，從內存中移除
                    del self.active_tokens[token]
                    return False
            
            # 從資料庫中檢查
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    SELECT token_id, expires_at, is_active 
                    FROM validation_tokens 
                    WHERE token_hash = %s AND is_active = TRUE
                ''', (token,))
            else:
                cursor.execute('''
                    SELECT token_id, expires_at, is_active 
                    FROM validation_tokens 
                    WHERE token_hash = ? AND is_active = 1
                ''', (token,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                token_id, expires_at, is_active = result
                expires_datetime = self._parse_datetime(expires_at)
                
                if datetime.now() < expires_datetime:
                    # 添加到內存中
                    self.active_tokens[token] = {
                        'token_id': token_id,
                        'expires_at': expires_datetime
                    }
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"❌ 驗證令牌失敗: {e}")
            return False
    
    def hash_serial(self, serial_key: str) -> str:
        """生成序號雜湊"""
        return hashlib.sha256(serial_key.encode('utf-8')).hexdigest()
    
    def _format_datetime(self, dt) -> str:
        """格式化日期時間（兼容 PostgreSQL 和 SQLite）"""
        if isinstance(dt, datetime):
            return dt.isoformat()
        return dt
    
    def _parse_datetime(self, dt_str) -> datetime:
        """解析日期時間字符串"""
        if isinstance(dt_str, datetime):
            return dt_str
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    
    def register_serial(self, serial_key: str, machine_id: str, tier: str, 
                       days: int, user_name: str = "使用者", 
                       encryption_type: str = "AES+XOR+ForceOnline") -> bool:
        """註冊序號到資料庫"""
        try:
            serial_hash = self.hash_serial(serial_key)
            created_date = datetime.now()
            expiry_date = created_date + timedelta(days=days)
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    INSERT INTO serials 
                    (serial_key, serial_hash, machine_id, user_name, tier, 
                     created_date, expiry_date, created_by, encryption_type,
                     force_online, validation_required, offline_disabled, server_validation_only)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (serial_key) DO UPDATE SET
                    machine_id = EXCLUDED.machine_id,
                    user_name = EXCLUDED.user_name,
                    tier = EXCLUDED.tier,
                    expiry_date = EXCLUDED.expiry_date,
                    encryption_type = EXCLUDED.encryption_type,
                    force_online = EXCLUDED.force_online,
                    validation_required = EXCLUDED.validation_required,
                    offline_disabled = EXCLUDED.offline_disabled,
                    server_validation_only = EXCLUDED.server_validation_only
                ''', (serial_key, serial_hash, machine_id, user_name, tier, 
                      created_date, expiry_date, 'api', encryption_type,
                      True, True, True, True))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO serials 
                    (serial_key, serial_hash, machine_id, user_name, tier, 
                     created_date, expiry_date, created_by, encryption_type,
                     force_online, validation_required, offline_disabled, server_validation_only)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (serial_key, serial_hash, machine_id, user_name, tier, 
                      self._format_datetime(created_date), self._format_datetime(expiry_date), 
                      'api', encryption_type, 1, 1, 1, 1))
            
            conn.commit()
            conn.close()
            
            # 記錄管理操作日誌
            self._log_admin_action('REGISTER_SERIAL', f'註冊序號: {tier}版本, {days}天', 
                                 serial_hash=serial_hash, machine_id=machine_id)
            
            logger.info(f"✅ 序號註冊成功: {serial_hash[:8]}...")
            return True
            
        except Exception as e:
            logger.error(f"❌ 註冊序號失敗: {e}")
            return False
    
    def validate_serial(self, serial_key: str, machine_id: str, 
                       client_ip: str = "127.0.0.1", validation_token: str = None) -> Dict[str, Any]:
        """驗證序號（強制在線版本）"""
        start_time = datetime.now()
        
        try:
            # 驗證令牌檢查
            if validation_token and not self.validate_token(validation_token):
                return {
                    'valid': False,
                    'error': '驗證令牌無效或已過期',
                    'requires_online': True,
                    'token_invalid': True
                }
            
            serial_hash = self.hash_serial(serial_key)
            current_time = datetime.now()
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # 檢查黑名單
            if self.use_postgresql:
                cursor.execute('''
                    SELECT reason, created_date FROM blacklist 
                    WHERE machine_id = %s AND is_active = TRUE
                ''', (machine_id,))
            else:
                cursor.execute('''
                    SELECT reason, created_date FROM blacklist 
                    WHERE machine_id = ? AND is_active = 1
                ''', (machine_id,))
            
            blacklist_result = cursor.fetchone()
            if blacklist_result:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'BLACKLISTED', client_ip, validation_method='force_online')
                conn.commit()
                conn.close()
                return {
                    'valid': False,
                    'error': f'機器在黑名單中: {blacklist_result[0]}',
                    'blacklisted': True,
                    'requires_online': True
                }
            
            # 檢查序號
            if self.use_postgresql:
                cursor.execute('''
                    SELECT machine_id, expiry_date, is_active, tier, user_name, check_count,
                           force_online, validation_required, offline_disabled, server_validation_only
                    FROM serials WHERE serial_hash = %s
                ''', (serial_hash,))
            else:
                cursor.execute('''
                    SELECT machine_id, expiry_date, is_active, tier, user_name, check_count,
                           force_online, validation_required, offline_disabled, server_validation_only
                    FROM serials WHERE serial_hash = ?
                ''', (serial_hash,))
            
            result = cursor.fetchone()
            
            if not result:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'NOT_FOUND', client_ip, validation_method='force_online')
                conn.commit()
                conn.close()
                return {
                    'valid': False, 
                    'error': '序號不存在',
                    'requires_online': True
                }
            
            (stored_machine_id, expiry_date, is_active, tier, user_name, check_count,
             force_online, validation_required, offline_disabled, server_validation_only) = result
            
            # 強制在線檢查
            if force_online or validation_required or offline_disabled or server_validation_only:
                if not validation_token:
                    self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                       'TOKEN_REQUIRED', client_ip, validation_method='force_online')
                    conn.commit()
                    conn.close()
                    return {
                        'valid': False,
                        'error': '此序號需要有效的驗證令牌',
                        'requires_online': True,
                        'token_required': True
                    }
            
            # 檢查機器ID綁定
            if stored_machine_id != machine_id:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'MACHINE_MISMATCH', client_ip, validation_method='force_online')
                conn.commit()
                conn.close()
                return {
                    'valid': False, 
                    'error': '序號已綁定到其他機器',
                    'requires_online': True
                }
            
            # 檢查是否被停用
            if not is_active:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'REVOKED', client_ip, validation_method='force_online')
                conn.commit()
                conn.close()
                return {
                    'valid': False, 
                    'error': '序號已被停用',
                    'requires_online': True
                }
            
            # 檢查過期時間
            expiry_dt = self._parse_datetime(expiry_date)
            if current_time > expiry_dt:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'EXPIRED', client_ip, validation_method='force_online')
                conn.commit()
                conn.close()
                return {
                    'valid': False, 
                    'error': '序號已過期', 
                    'expired': True,
                    'requires_online': True
                }
            
            # 更新檢查時間和次數
            new_check_count = (check_count or 0) + 1
            if self.use_postgresql:
                cursor.execute('''
                    UPDATE serials 
                    SET last_check_time = %s, check_count = %s, 
                        last_validation_ip = %s, validation_count = validation_count + 1
                    WHERE serial_hash = %s
                ''', (current_time, new_check_count, client_ip, serial_hash))
            else:
                cursor.execute('''
                    UPDATE serials 
                    SET last_check_time = ?, check_count = ?, 
                        last_validation_ip = ?, validation_count = validation_count + 1
                    WHERE serial_hash = ?
                ''', (self._format_datetime(current_time), new_check_count, client_ip, serial_hash))
            
            # 記錄成功驗證
            response_time = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_validation(cursor, serial_hash, machine_id, current_time, 
                               'VALID', client_ip, validation_method='force_online',
                               response_time=response_time)
            
            conn.commit()
            conn.close()
            
            remaining_days = (expiry_dt - current_time).days
            
            return {
                'valid': True,
                'tier': tier,
                'user_name': user_name,
                'expiry_date': self._format_datetime(expiry_dt),
                'remaining_days': remaining_days,
                'check_count': new_check_count,
                'force_online': True,
                'validation_method': 'force_online',
                'response_time_ms': response_time
            }
            
        except Exception as e:
            logger.error(f"❌ 驗證過程錯誤: {e}")
            return {
                'valid': False, 
                'error': f'驗證過程錯誤: {str(e)}',
                'requires_online': True
            }
    
    def _log_validation(self, cursor, serial_hash: str, machine_id: str, 
                       validation_time: datetime, result: str, client_ip: str,
                       validation_method: str = 'force_online', response_time: int = None):
        """記錄驗證日誌"""
        try:
            if self.use_postgresql:
                cursor.execute('''
                    INSERT INTO validation_logs 
                    (serial_hash, machine_id, validation_time, result, client_ip, 
                     validation_method, server_response_time)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                ''', (serial_hash, machine_id, validation_time, result, client_ip, 
                      validation_method, response_time))
            else:
                cursor.execute('''
                    INSERT INTO validation_logs 
                    (serial_hash, machine_id, validation_time, result, client_ip, 
                     validation_method, server_response_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (serial_hash, machine_id, self._format_datetime(validation_time), 
                      result, client_ip, validation_method, response_time))
        except Exception as e:
            logger.error(f"❌ 記錄驗證日誌失敗: {e}")
    
    def _log_admin_action(self, action_type: str, description: str, 
                         serial_hash: str = None, machine_id: str = None,
                         success: bool = True, error_message: str = None):
        """記錄管理操作日誌"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    INSERT INTO admin_logs 
                    (action_type, action_description, target_serial_hash, target_machine_id,
                     success, error_message)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (action_type, description, serial_hash, machine_id, success, error_message))
            else:
                cursor.execute('''
                    INSERT INTO admin_logs 
                    (action_type, action_description, target_serial_hash, target_machine_id,
                     success, error_message, performed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (action_type, description, serial_hash, machine_id, 
                      1 if success else 0, error_message, self._format_datetime(datetime.now())))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"❌ 記錄管理日誌失敗: {e}")
    
    def revoke_serial(self, serial_key: str, reason: str = "管理員停用") -> bool:
        """停用序號"""
        try:
            serial_hash = self.hash_serial(serial_key)
            revoked_date = datetime.now()
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = FALSE, revoked_date = %s, revoked_reason = %s
                    WHERE serial_hash = %s
                ''', (revoked_date, reason, serial_hash))
            else:
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = 0, revoked_date = ?, revoked_reason = ?
                    WHERE serial_hash = ?
                ''', (self._format_datetime(revoked_date), reason, serial_hash))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            if success:
                self._log_admin_action('REVOKE_SERIAL', f'停用序號: {reason}', serial_hash=serial_hash)
                logger.info(f"✅ 序號停用成功: {serial_hash[:8]}...")
            
            return success
            
        except Exception as e:
            logger.error(f"❌ 停用序號失敗: {e}")
            return False
    
    def restore_serial(self, serial_key: str) -> bool:
        """恢復序號"""
        try:
            serial_hash = self.hash_serial(serial_key)
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = TRUE, revoked_date = NULL, revoked_reason = NULL
                    WHERE serial_hash = %s
                ''', (serial_hash,))
            else:
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = 1, revoked_date = NULL, revoked_reason = NULL
                    WHERE serial_hash = ?
                ''', (serial_hash,))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            if success:
                self._log_admin_action('RESTORE_SERIAL', '恢復序號', serial_hash=serial_hash)
                logger.info(f"✅ 序號恢復成功: {serial_hash[:8]}...")
            
            return success
            
        except Exception as e:
            logger.error(f"❌ 恢復序號失敗: {e}")
            return False
    
    def add_to_blacklist(self, machine_id: str, reason: str = "違規使用") -> bool:
        """添加到黑名單"""
        try:
            created_date = datetime.now()
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    INSERT INTO blacklist 
                    (machine_id, reason, created_date, is_active)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (machine_id) DO UPDATE SET
                    reason = EXCLUDED.reason,
                    created_date = EXCLUDED.created_date,
                    is_active = TRUE
                ''', (machine_id, reason, created_date, True))
                
                # 同時停用該機器的所有序號
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = FALSE, revoked_date = %s, revoked_reason = %s
                    WHERE machine_id = %s AND is_active = TRUE
                ''', (created_date, f"黑名單自動停用: {reason}", machine_id))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO blacklist 
                    (machine_id, reason, created_date, is_active)
                    VALUES (?, ?, ?, ?)
                ''', (machine_id, reason, self._format_datetime(created_date), 1))
                
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = 0, revoked_date = ?, revoked_reason = ?
                    WHERE machine_id = ? AND is_active = 1
                ''', (self._format_datetime(created_date), f"黑名單自動停用: {reason}", machine_id))
            
            conn.commit()
            conn.close()
            
            self._log_admin_action('ADD_BLACKLIST', f'添加黑名單: {reason}', machine_id=machine_id)
            logger.info(f"✅ 黑名單添加成功: {machine_id}")
            return True
            
        except Exception as e:
            logger.error(f"❌ 添加黑名單失敗: {e}")
            return False
    
    def remove_from_blacklist(self, machine_id: str) -> bool:
        """從黑名單移除"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    UPDATE blacklist SET is_active = FALSE 
                    WHERE machine_id = %s
                ''', (machine_id,))
            else:
                cursor.execute('''
                    UPDATE blacklist SET is_active = 0 
                    WHERE machine_id = ?
                ''', (machine_id,))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            if success:
                self._log_admin_action('REMOVE_BLACKLIST', '移除黑名單', machine_id=machine_id)
                logger.info(f"✅ 黑名單移除成功: {machine_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"❌ 移除黑名單失敗: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """獲取統計資訊"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # 總序號數
            cursor.execute('SELECT COUNT(*) FROM serials')
            total_serials = cursor.fetchone()[0]
            
            # 活躍序號數
            if self.use_postgresql:
                cursor.execute('SELECT COUNT(*) FROM serials WHERE is_active = TRUE')
                active_serials = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM serials WHERE force_online = TRUE')
                force_online_serials = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM blacklist WHERE is_active = TRUE')
                blacklist_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM validation_logs WHERE DATE(validation_time) = CURRENT_DATE")
                today_validations = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM validation_logs WHERE result = 'VALID' AND DATE(validation_time) = CURRENT_DATE")
                today_successful = cursor.fetchone()[0]
                
            else:
                cursor.execute('SELECT COUNT(*) FROM serials WHERE is_active = 1')
                active_serials = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM serials WHERE force_online = 1')
                force_online_serials = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM blacklist WHERE is_active = 1')
                blacklist_count = cursor.fetchone()[0]
                
                today = datetime.now().date().isoformat()
                cursor.execute('SELECT COUNT(*) FROM validation_logs WHERE DATE(validation_time) = ?', (today,))
                today_validations = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM validation_logs WHERE result = 'VALID' AND DATE(validation_time) = ?", (today,))
                today_successful = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_serials': total_serials,
                'active_serials': active_serials,
                'revoked_serials': total_serials - active_serials,
                'force_online_serials': force_online_serials,
                'blacklist_count': blacklist_count,
                'today_validations': today_validations,
                'today_successful_validations': today_successful,
                'today_failed_validations': today_validations - today_successful,
                'success_rate_today': round((today_successful / today_validations * 100) if today_validations > 0 else 0, 2),
                'database_type': 'PostgreSQL' if self.use_postgresql else 'SQLite',
                'database_url_found': bool(self.database_url),
                'psycopg2_available': PSYCOPG2_AVAILABLE,
                'force_online_enabled': True,
                'version': '5.2.0'
            }
            
        except Exception as e:
            logger.error(f"❌ 獲取統計失敗: {e}")
            return {
                'database_type': 'PostgreSQL' if self.use_postgresql else 'SQLite',
                'database_url_found': bool(self.database_url),
                'psycopg2_available': PSYCOPG2_AVAILABLE,
                'force_online_enabled': True,
                'version': '5.2.0',
                'error': str(e)
            }

# 初始化資料庫管理器
try:
    print("🚀 初始化資料庫管理器...")
    db_manager = DatabaseManager()
    print("✅ 資料庫管理器初始化完成")
    logger.info("✅ 資料庫管理器初始化成功")
except Exception as e:
    print(f"❌ 資料庫管理器初始化失敗: {e}")
    logger.error(f"❌ 資料庫管理器初始化失敗: {e}")
    sys.exit(1)

# API 路由
@app.route('/')
def home():
    """首頁"""
    stats = db_manager.get_statistics()
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BOSS檢測器 Railway 驗證伺服器 (強制在線增強版)</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { 
                font-family: 'Microsoft JhengHei UI', Arial; 
                margin: 0; 
                padding: 20px; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
            }
            .container { 
                max-width: 1200px; 
                margin: 0 auto; 
                background: rgba(255, 255, 255, 0.95); 
                padding: 30px; 
                border-radius: 15px; 
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                backdrop-filter: blur(10px);
            }
            .header {
                text-align: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 2px solid #e2e8f0;
            }
            .title {
                font-size: 2.5em;
                color: #2563eb;
                margin: 0;
                text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.1);
            }
            .subtitle {
                font-size: 1.2em;
                color: #64748b;
                margin: 10px 0;
            }
            .status { 
                padding: 15px; 
                margin: 15px 0; 
                border-radius: 10px; 
                border-left: 5px solid;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            .success { 
                background: linear-gradient(135deg, #d4edda, #c3e6cb); 
                color: #155724; 
                border-left-color: #28a745;
            }
            .info { 
                background: linear-gradient(135deg, #d1ecf1, #bee5eb); 
                color: #0c5460; 
                border-left-color: #17a2b8;
            }
            .warning { 
                background: linear-gradient(135deg, #fff3cd, #ffeaa7); 
                color: #856404; 
                border-left-color: #ffc107;
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }
            .stat-card {
                background: linear-gradient(135deg, #f8fafc, #e2e8f0);
                padding: 20px;
                border-radius: 10px;
                text-align: center;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                transition: transform 0.3s ease;
            }
            .stat-card:hover {
                transform: translateY(-5px);
            }
            .stat-value {
                font-size: 2em;
                font-weight: bold;
                color: #2563eb;
                margin-bottom: 10px;
            }
            .stat-label {
                color: #64748b;
                font-size: 0.9em;
            }
            table { 
                width: 100%; 
                border-collapse: collapse; 
                margin: 20px 0; 
                background: white;
                border-radius: 10px;
                overflow: hidden;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
            th, td { 
                padding: 15px; 
                text-align: left; 
                border-bottom: 1px solid #e2e8f0; 
            }
            th { 
                background: linear-gradient(135deg, #2563eb, #1d4ed8); 
                color: white;
                font-weight: 600;
            }
            tr:hover {
                background-color: #f8fafc;
            }
            .db-type { 
                font-weight: bold; 
                color: #059669; 
                padding: 5px 10px;
                background: #ecfdf5;
                border-radius: 5px;
            }
            .api-section {
                background: linear-gradient(135deg, #f8fafc, #e2e8f0);
                padding: 20px;
                border-radius: 10px;
                margin-top: 30px;
            }
            .api-endpoint {
                background: white;
                padding: 10px 15px;
                margin: 10px 0;
                border-radius: 5px;
                font-family: 'Consolas', monospace;
                border-left: 4px solid #2563eb;
            }
            .badge {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 0.8em;
                font-weight: bold;
                margin-left: 10px;
            }
            .badge-success { background: #d4edda; color: #155724; }
            .badge-warning { background: #fff3cd; color: #856404; }
            .badge-info { background: #d1ecf1; color: #0c5460; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="title">🛡️ BOSS檢測器 Railway 驗證伺服器</h1>
                <p class="subtitle">強制在線增強版 v5.2.0 | 企業級安全保護</p>
                <p class="subtitle">{{ current_time }}</p>
            </div>
            
            <div class="status success">
                ✅ <strong>伺服器運行正常</strong> - 強制在線驗證系統已啟動
            </div>
            
            {% if stats.database_type == 'PostgreSQL' %}
            <div class="status success">
                🐘 <span class="db-type">PostgreSQL</span> 資料庫已連接 - 數據永久保存，支援高併發訪問
            </div>
            {% else %}
            <div class="status warning">
                🗄️ <span class="db-type">SQLite</span> 資料庫 - 調試模式運行
                <br><small>DATABASE_URL: {{ '已配置' if stats.database_url_found else '未配置' }} | 
                psycopg2: {{ '可用' if stats.psycopg2_available else '不可用' }}</small>
            </div>
            {% endif %}
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{{ stats.total_serials }}</div>
                    <div class="stat-label">總序號數</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.active_serials }}</div>
                    <div class="stat-label">活躍序號</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.force_online_serials }}</div>
                    <div class="stat-label">強制在線序號</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.today_validations }}</div>
                    <div class="stat-label">今日驗證次數</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.success_rate_today }}%</div>
                    <div class="stat-label">今日成功率</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ stats.blacklist_count }}</div>
                    <div class="stat-label">黑名單數量</div>
                </div>
            </div>
            
            <h2>📊 系統狀態詳情</h2>
            <table>
                <tr><th>項目</th><th>狀態</th></tr>
                <tr><td>部署平台</td><td>Railway.app <span class="badge badge-success">雲端</span></td></tr>
                <tr><td>資料庫類型</td><td><span class="db-type">{{ stats.database_type }}</span></td></tr>
                <tr><td>強制在線模式</td><td>✅ 已啟用 <span class="badge badge-success">企業級</span></td></tr>
                <tr><td>離線保護</td><td>✅ 已啟用 <span class="badge badge-success">防破解</span></td></tr>
                <tr><td>總序號數</td><td>{{ stats.total_serials }}</td></tr>
                <tr><td>活躍序號</td><td>{{ stats.active_serials }} <span class="badge badge-success">在線</span></td></tr>
                <tr><td>停用序號</td><td>{{ stats.revoked_serials }}</td></tr>
                <tr><td>強制在線序號</td><td>{{ stats.force_online_serials }} <span class="badge badge-info">安全增強</span></td></tr>
                <tr><td>黑名單機器</td><td>{{ stats.blacklist_count }}</td></tr>
                <tr><td>今日驗證</td><td>{{ stats.today_validations }} (成功: {{ stats.today_successful_validations }})</td></tr>
                <tr><td>今日成功率</td><td>{{ stats.success_rate_today }}% <span class="badge badge-{% if stats.success_rate_today >= 90 %}success{% elif stats.success_rate_today >= 70 %}warning{% else %}danger{% endif %}">{% if stats.success_rate_today >= 90 %}優秀{% elif stats.success_rate_today >= 70 %}良好{% else %}需改進{% endif %}</span></td></tr>
            </table>
            
            <div class="api-section">
                <h2>🔗 API端點 (強制在線增強版)</h2>
                
                <h3>🔐 驗證令牌系統</h3>
                <div class="api-endpoint">POST /api/auth/token <span class="badge badge-info">NEW</span> - 獲取驗證令牌</div>
                
                <h3>📝 序號管理</h3>
                <div class="api-endpoint">POST /api/validate <span class="badge badge-success">增強</span> - 強制在線驗證序號</div>
                <div class="api-endpoint">POST /api/validate/enhanced <span class="badge badge-info">NEW</span> - 增強版驗證</div>
                <div class="api-endpoint">POST /api/validate/force <span class="badge badge-info">NEW</span> - 強制驗證</div>
                <div class="api-endpoint">POST /api/register <span class="badge badge-success">增強</span> - 註冊序號</div>
                <div class="api-endpoint">POST /api/register/enhanced <span class="badge badge-info">NEW</span> - 增強版註冊</div>
                <div class="api-endpoint">POST /api/register/force <span class="badge badge-info">NEW</span> - 強制註冊</div>
                
                <h3>⚙️ 序號操作</h3>
                <div class="api-endpoint">POST /api/revoke - 停用序號</div>
                <div class="api-endpoint">POST /api/restore - 恢復序號</div>
                <div class="api-endpoint">POST /api/serial/status - 檢查序號狀態</div>
                
                <h3>🚫 黑名單管理</h3>
                <div class="api-endpoint">POST /api/blacklist - 添加黑名單</div>
                <div class="api-endpoint">POST /api/blacklist/remove - 移除黑名單</div>
                <div class="api-endpoint">POST /api/blacklist/check - 檢查黑名單狀態</div>
                
                <h3>📊 系統資訊</h3>
                <div class="api-endpoint">GET /api/stats - 獲取統計資訊</div>
                <div class="api-endpoint">GET /api/health - 健康檢查</div>
                
                <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 8px;">
                    <strong>⚠️ 重要說明：</strong><br>
                    • 所有強制在線序號都需要有效的驗證令牌<br>
                    • 離線版本程序無法驗證強制在線序號<br>
                    • 支援企業級安全防護和防破解機制<br>
                    • 建議在生產環境中使用 PostgreSQL 資料庫
                </div>
            </div>
            
            <div style="text-align: center; margin-top: 30px; padding: 20px; background: linear-gradient(135deg, #f1f5f9, #e2e8f0); border-radius: 10px;">
                <p style="margin: 0; color: #64748b;">
                    <strong>BOSS檢測器 Railway 驗證伺服器</strong> v5.2.0<br>
                    作者: @yyv3vnn | 強制在線增強版 | 企業級安全保護
                </p>
            </div>
        </div>
    </body>
    </html>
    ''', current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), stats=stats)

@app.route('/api/health')
def health_check():
    """健康檢查"""
    stats = db_manager.get_statistics()
    return jsonify({
        'status': 'healthy',
        'server': 'BOSS檢測器 Railway 驗證伺服器 (強制在線增強版)',
        'version': '5.2.0',
        'timestamp': datetime.now().isoformat(),
        'database': stats.get('database_type', 'Unknown'),
        'force_online_enabled': True,
        'debug_info': {
            'database_url_found': stats.get('database_url_found', False),
            'psycopg2_available': stats.get('psycopg2_available', False)
        },
        'stats': stats,
        'endpoints': {
            'auth': ['/api/auth/token'],
            'validation': ['/api/validate', '/api/validate/enhanced', '/api/validate/force'],
            'registration': ['/api/register', '/api/register/enhanced', '/api/register/force'],
            'management': ['/api/revoke', '/api/restore', '/api/serial/status'],
            'blacklist': ['/api/blacklist', '/api/blacklist/remove', '/api/blacklist/check'],
            'system': ['/api/stats', '/api/health']
        }
    })

# ==================== 驗證令牌系統 ====================

@app.route('/api/auth/token', methods=['POST'])
def get_validation_token():
    """獲取驗證令牌"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '無效的請求資料'}), 400
        
        admin_key = data.get('admin_key')
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        request_type = data.get('request_type', 'validation')
        
        if request_type not in ['validation', 'admin', 'system']:
            return jsonify({'success': False, 'error': '無效的請求類型'}), 400
        
        result = db_manager.generate_validation_token()
        
        if result.get('success', False):
            logger.info(f"✅ 驗證令牌生成成功: {request_type}")
            return jsonify(result)
        else:
            return jsonify(result), 500
            
    except Exception as e:
        logger.error(f"❌ 獲取驗證令牌API錯誤: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== 驗證系統 ====================

@app.route('/api/validate', methods=['POST'])
def validate_serial():
    """驗證序號 (標準版本)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'error': '無效的請求資料'}), 400
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        validation_token = data.get('validation_token')
        
        if not serial_key or not machine_id:
            return jsonify({'valid': False, 'error': '缺少必要參數'}), 400
        
        client_ip = request.remote_addr
        result = db_manager.validate_serial(serial_key, machine_id, client_ip, validation_token)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"❌ 驗證API錯誤: {e}")
        return jsonify({'valid': False, 'error': f'驗證失敗: {str(e)}'}), 500

@app.route('/api/validate/enhanced', methods=['POST'])
def validate_serial_enhanced():
    """增強版驗證序號"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'error': '無效的請求資料'}), 400
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        validation_token = data.get('validation_token')
        force_online = data.get('force_online', True)
        checksum = data.get('checksum')
        
        if not serial_key or not machine_id:
            return jsonify({'valid': False, 'error': '缺少必要參數'}), 400
        
        # 增強版驗證需要令牌
        if not validation_token:
            return jsonify({
                'valid': False, 
                'error': '增強版驗證需要有效的驗證令牌',
                'requires_token': True
            }), 401
        
        # 驗證校驗和
        if checksum:
            expected_checksum = hashlib.sha256(f"{serial_key}{machine_id}".encode()).hexdigest()
            if checksum != expected_checksum:
                return jsonify({
                    'valid': False, 
                    'error': '請求校驗和驗證失敗',
                    'checksum_invalid': True
                }), 400
        
        client_ip = request.remote_addr
        result = db_manager.validate_serial(serial_key, machine_id, client_ip, validation_token)
        
        # 添加增強版響應信息
        if result.get('valid', False):
            result['enhanced_validation'] = True
            result['force_online_verified'] = True
            result['validation_level'] = 'enhanced'
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"❌ 增強版驗證API錯誤: {e}")
        return jsonify({'valid': False, 'error': f'增強版驗證失敗: {str(e)}'}), 500

@app.route('/api/validate/force', methods=['POST'])
def validate_serial_force():
    """強制驗證序號"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'error': '無效的請求資料'}), 400
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        validation_token = data.get('validation_token')
        
        if not serial_key or not machine_id or not validation_token:
            return jsonify({
                'valid': False, 
                'error': '強制驗證需要序號、機器ID和驗證令牌',
                'requires_all_params': True
            }), 400
        
        client_ip = request.remote_addr
        result = db_manager.validate_serial(serial_key, machine_id, client_ip, validation_token)
        
        # 強制驗證標記
        if result.get('valid', False):
            result['force_validation'] = True
            result['offline_disabled'] = True
            result['validation_level'] = 'force'
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"❌ 強制驗證API錯誤: {e}")
        return jsonify({'valid': False, 'error': f'強制驗證失敗: {str(e)}'}), 500

# ==================== 註冊系統 ====================

@app.route('/api/register', methods=['POST'])
def register_serial():
    """註冊序號 (標準版本)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '無效的請求資料'}), 400
        
        admin_key = data.get('admin_key')
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        tier = data.get('tier', 'trial')
        days = data.get('days', 7)
        user_name = data.get('user_name', '使用者')
        encryption_type = data.get('encryption_type', 'AES+XOR')
        
        if not serial_key or not machine_id:
            return jsonify({'success': False, 'error': '缺少必要參數'}), 400
        
        success = db_manager.register_serial(serial_key, machine_id, tier, days, user_name, encryption_type)
        
        return jsonify({
            'success': success,
            'message': '序號註冊成功' if success else '序號註冊失敗',
            'registered': success
        })
        
    except Exception as e:
        logger.error(f"❌ 註冊API錯誤: {e}")
        return jsonify({'success': False, 'error': f'註冊失敗: {str(e)}'}), 500

@app.route('/api/register/enhanced', methods=['POST'])
def register_serial_enhanced():
    """增強版註冊序號"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '無效的請求資料'}), 400
        
        admin_key = data.get('admin_key')
        validation_token = data.get('validation_token')
        
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        # 增強版註冊可能需要驗證令牌
        if validation_token and not db_manager.validate_token(validation_token):
            return jsonify({
                'success': False, 
                'error': '驗證令牌無效或已過期',
                'token_invalid': True
            }), 401
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        tier = data.get('tier', 'trial')
        days = data.get('days', 7)
        user_name = data.get('user_name', '使用者')
        encryption_type = data.get('encryption_type', 'AES+XOR+ForceOnline')
        force_online = data.get('force_online', True)
        checksum = data.get('checksum')
        
        if not serial_key or not machine_id:
            return jsonify({'success': False, 'error': '缺少必要參數'}), 400
        
        # 驗證校驗和
        if checksum:
            expected_checksum = hashlib.sha256(f"{serial_key}{machine_id}{admin_key}".encode()).hexdigest()
            if checksum != expected_checksum:
                return jsonify({
                    'success': False, 
                    'error': '註冊校驗和驗證失敗',
                    'checksum_invalid': True
                }), 400
        
        success = db_manager.register_serial(serial_key, machine_id, tier, days, user_name, encryption_type)
        
        response = {
            'success': success,
            'message': '增強版序號註冊成功' if success else '增強版序號註冊失敗',
            'registered': success,
            'enhanced_registration': True,
            'force_online': force_online
        }
        
        # 如果需要，生成新的驗證令牌
        if success and data.get('generate_new_token', False):
            token_result = db_manager.generate_validation_token()
            if token_result.get('success', False):
                response['new_token'] = token_result.get('token')
                response['token_expires'] = token_result.get('expires_at')
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"❌ 增強版註冊API錯誤: {e}")
        return jsonify({'success': False, 'error': f'增強版註冊失敗: {str(e)}'}), 500

@app.route('/api/register/force', methods=['POST'])
def register_serial_force():
    """強制註冊序號"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '無效的請求資料'}), 400
        
        admin_key = data.get('admin_key')
        validation_token = data.get('validation_token')
        
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        # 強制註冊必須有驗證令牌
        if not validation_token or not db_manager.validate_token(validation_token):
            return jsonify({
                'success': False, 
                'error': '強制註冊需要有效的驗證令牌',
                'token_required': True
            }), 401
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        tier = data.get('tier', 'trial')
        days = data.get('days', 7)
        user_name = data.get('user_name', '使用者')
        encryption_type = data.get('encryption_type', 'AES+XOR+ForceOnline')
        version = data.get('version', '6.0.0')
        
        if not serial_key or not machine_id:
            return jsonify({'success': False, 'error': '缺少必要參數'}), 400
        
        success = db_manager.register_serial(serial_key, machine_id, tier, days, user_name, encryption_type)
        
        return jsonify({
            'success': success,
            'message': '強制註冊成功' if success else '強制註冊失敗',
            'registered': success,
            'force_registered': success,
            'force_online': True,
            'offline_disabled': True,
            'validation_level': 'force'
        })
        
    except Exception as e:
        logger.error(f"❌ 強制註冊API錯誤: {e}")
        return jsonify({'success': False, 'error': f'強制註冊失敗: {str(e)}'}), 500

# ==================== 序號管理系統 ====================

@app.route('/api/revoke', methods=['POST'])
def revoke_serial():
    """停用序號"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '無效的請求資料'}), 400
        
        admin_key = data.get('admin_key')
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        serial_key = data.get('serial_key')
        reason = data.get('reason', '管理員停用')
        
        if not serial_key:
            return jsonify({'success': False, 'error': '缺少序號'}), 400
        
        success = db_manager.revoke_serial(serial_key, reason)
        
        return jsonify({
            'success': success,
            'message': '序號停用成功' if success else '序號停用失敗'
        })
        
    except Exception as e:
        logger.error(f"❌ 停用API錯誤: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/restore', methods=['POST'])
def restore_serial():
    """恢復序號"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '無效的請求資料'}), 400
        
        admin_key = data.get('admin_key')
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        serial_key = data.get('serial_key')
        if not serial_key:
            return jsonify({'success': False, 'error': '缺少序號'}), 400
        
        success = db_manager.restore_serial(serial_key)
        
        return jsonify({
            'success': success,
            'message': '序號恢復成功' if success else '序號恢復失敗'
        })
        
    except Exception as e:
        logger.error(f"❌ 恢復API錯誤: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/serial/status', methods=['POST'])
def check_serial_status():
    """檢查序號狀態"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'found': False, 'error': '無效的請求資料'}), 400
        
        admin_key = data.get('admin_key')
        if admin_key != db_manager.admin_key:
            return jsonify({'found': False, 'error': '管理員認證失敗'}), 403
        
        serial_key = data.get('serial_key')
        if not serial_key:
            return jsonify({'found': False, 'error': '缺少序號'}), 400
        
        serial_hash = db_manager.hash_serial(serial_key)
        
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        if db_manager.use_postgresql:
            cursor.execute('''
                SELECT machine_id, user_name, tier, is_active, revoked_date, revoked_reason,
                       created_date, expiry_date, check_count, force_online, validation_required
                FROM serials WHERE serial_hash = %s
            ''', (serial_hash,))
        else:
            cursor.execute('''
                SELECT machine_id, user_name, tier, is_active, revoked_date, revoked_reason,
                       created_date, expiry_date, check_count, force_online, validation_required
                FROM serials WHERE serial_hash = ?
            ''', (serial_hash,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            (machine_id, user_name, tier, is_active, revoked_date, revoked_reason,
             created_date, expiry_date, check_count, force_online, validation_required) = result
            
            return jsonify({
                'found': True,
                'is_active': bool(is_active),
                'info': {
                    'machine_id': machine_id,
                    'user_name': user_name,
                    'tier': tier,
                    'created_date': db_manager._format_datetime(created_date),
                    'expiry_date': db_manager._format_datetime(expiry_date),
                    'check_count': check_count or 0,
                    'force_online': bool(force_online),
                    'validation_required': bool(validation_required),
                    'revoked_date': db_manager._format_datetime(revoked_date) if revoked_date else None,
                    'revoked_reason': revoked_reason
                }
            })
        else:
            return jsonify({'found': False})
            
    except Exception as e:
        logger.error(f"❌ 檢查序號狀態API錯誤: {e}")
        return jsonify({'found': False, 'error': str(e)}), 500

# ==================== 黑名單管理系統 ====================

@app.route('/api/blacklist', methods=['POST'])
def add_blacklist():
    """添加黑名單"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '無效的請求資料'}), 400
        
        admin_key = data.get('admin_key')
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        machine_id = data.get('machine_id')
        reason = data.get('reason', '違規使用')
        
        if not machine_id:
            return jsonify({'success': False, 'error': '缺少機器ID'}), 400
        
        success = db_manager.add_to_blacklist(machine_id, reason)
        
        return jsonify({
            'success': success,
            'message': '黑名單添加成功' if success else '黑名單添加失敗'
        })
        
    except Exception as e:
        logger.error(f"❌ 黑名單API錯誤: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/blacklist/remove', methods=['POST'])
def remove_blacklist():
    """移除黑名單"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '無效的請求資料'}), 400
        
        admin_key = data.get('admin_key')
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        machine_id = data.get('machine_id')
        if not machine_id:
            return jsonify({'success': False, 'error': '缺少機器ID'}), 400
        
        success = db_manager.remove_from_blacklist(machine_id)
        
        return jsonify({
            'success': success,
            'message': '黑名單移除成功' if success else '黑名單移除失敗'
        })
        
    except Exception as e:
        logger.error(f"❌ 移除黑名單API錯誤: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/blacklist/check', methods=['POST'])
def check_blacklist():
    """檢查黑名單狀態"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'blacklisted': False, 'error': '無效的請求資料'}), 400
        
        machine_id = data.get('machine_id')
        if not machine_id:
            return jsonify({'blacklisted': False, 'error': '缺少機器ID'}), 400
        
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        if db_manager.use_postgresql:
            cursor.execute('''
                SELECT reason, created_date, severity, expires_at 
                FROM blacklist 
                WHERE machine_id = %s AND is_active = TRUE
            ''', (machine_id,))
        else:
            cursor.execute('''
                SELECT reason, created_date, severity, expires_at 
                FROM blacklist 
                WHERE machine_id = ? AND is_active = 1
            ''', (machine_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            reason, created_date, severity, expires_at = result
            
            # 檢查是否已過期
            if expires_at:
                expires_datetime = db_manager._parse_datetime(expires_at)
                if datetime.now() > expires_datetime:
                    return jsonify({'blacklisted': False, 'expired': True})
            
            return jsonify({
                'blacklisted': True,
                'info': {
                    'reason': reason,
                    'created_date': db_manager._format_datetime(created_date),
                    'severity': severity or 'medium',
                    'expires_at': db_manager._format_datetime(expires_at) if expires_at else None
                }
            })
        else:
            return jsonify({'blacklisted': False})
            
    except Exception as e:
        logger.error(f"❌ 檢查黑名單API錯誤: {e}")
        return jsonify({'blacklisted': False, 'error': str(e)}), 500

# ==================== 系統統計 ====================

@app.route('/api/stats')
def get_stats():
    """獲取統計資訊"""
    try:
        stats = db_manager.get_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"❌ 統計API錯誤: {e}")
        return jsonify({'error': str(e)}), 500

# ==================== 額外的兼容性端點 ====================

@app.route('/api/add', methods=['POST'])
def add_serial_legacy():
    """舊版添加序號端點 (兼容性)"""
    return register_serial()

@app.route('/health')
def health_simple():
    """簡化健康檢查"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '5.2.0'
    })

@app.route('/api/status')
def api_status():
    """API狀態檢查"""
    return jsonify({
        'api_status': 'operational',
        'database_connected': True,
        'force_online_enabled': True,
        'endpoints_available': 15,
        'version': '5.2.0'
    })

# ==================== 錯誤處理 ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': '端點不存在',
        'available_endpoints': {
            'auth': '/api/auth/token',
            'validation': '/api/validate, /api/validate/enhanced, /api/validate/force',
            'registration': '/api/register, /api/register/enhanced, /api/register/force',
            'management': '/api/revoke, /api/restore, /api/serial/status',
            'blacklist': '/api/blacklist, /api/blacklist/remove, /api/blacklist/check',
            'system': '/api/stats, /api/health'
        }
    }), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"❌ 伺服器內部錯誤: {error}")
    return jsonify({'error': '伺服器內部錯誤'}), 500

@app.errorhandler(403)
def forbidden_error(error):
    return jsonify({'error': '訪問被拒絕 - 需要有效的管理員認證'}), 403

@app.errorhandler(401)
def unauthorized_error(error):
    return jsonify({'error': '未授權 - 需要有效的驗證令牌'}), 401

# ==================== 主程式入口點 ====================

if __name__ == '__main__':
    print("🚀 啟動 BOSS檢測器 Railway 驗證伺服器 (強制在線增強版)...")
    print(f"📍 資料庫類型: {'PostgreSQL' if db_manager.use_postgresql else 'SQLite'}")
    print(f"🔍 DATABASE_URL 存在: {bool(db_manager.database_url)}")
    print(f"🔍 psycopg2 可用: {PSYCOPG2_AVAILABLE}")
    print("📡 可用的 API 端點:")
    print("  GET  / - 首頁")
    print("  GET  /api/health - 健康檢查")
    print("  POST /api/auth/token - 獲取驗證令牌 [NEW]")
    print("  POST /api/validate - 驗證序號")
    print("  POST /api/validate/enhanced - 增強版驗證 [NEW]")
    print("  POST /api/validate/force - 強制驗證 [NEW]")
    print("  POST /api/register - 註冊序號")
    print("  POST /api/register/enhanced - 增強版註冊 [NEW]")
    print("  POST /api/register/force - 強制註冊 [NEW]")
    print("  POST /api/revoke - 停用序號")
    print("  POST /api/restore - 恢復序號")
    print("  POST /api/serial/status - 檢查序號狀態")
    print("  POST /api/blacklist - 添加黑名單")
    print("  POST /api/blacklist/remove - 移除黑名單")
    print("  POST /api/blacklist/check - 檢查黑名單")
    print("  GET  /api/stats - 獲取統計")
    print("🔐 強制在線功能: 已啟用")
    print("🛡️ 企業級安全保護: 已啟用")
    print("="*50)
    
    # 開發模式
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
