#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================
  BOSS檢測器 Railway Flask 應用 (PostgreSQL版) v6.0.0
===========================================
作者: @yyv3vnn (Telegram)
功能: Railway 部署的 Flask API 伺服器 (支援強制在線驗證)
版本: 6.0.0 (強制在線增強版)
更新: 2025-08-22
新增: 強制在線驗證端點 + Token認證 + 完整PostgreSQL支援
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
import secrets
import time

# 環境變量檢查
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
app.config['SECRET_KEY'] = 'boss_detector_2025_enhanced_secret_key_v6'
app.config['JSON_AS_ASCII'] = False

class EnhancedDatabaseManager:
    """增強版資料庫管理器 - 支援強制在線驗證"""
    
    def __init__(self):
        # 管理員金鑰（對應lcsss.py中的admin_key）
        self.admin_key = "boss_admin_2025_enhanced_key_v6"
        self.master_key = "boss_detector_2025_enhanced_aes_master_key_v6"
        
        # Token管理
        self.active_tokens = {}  # {token: {expires_at: datetime, user: str}}
        self.token_lifetime = timedelta(hours=24)  # Token有效期24小時
        
        self.database_url = os.environ.get('DATABASE_URL')
        
        print(f"🔍 初始化增強版資料庫管理器...")
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
                self.db_path = "boss_detector_enhanced.db"
                logger.info("🗄️ 使用 SQLite 資料庫 (PostgreSQL 連接失敗)")
                self.init_sqlite()
        else:
            # 回退到 SQLite
            self.use_postgresql = False
            self.db_path = "boss_detector_enhanced.db"
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
        """初始化 PostgreSQL 資料庫 - 增強版表結構"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            print("🔧 創建增強版 PostgreSQL 表...")
            
            # 增強版序號表 - 支援強制在線驗證
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS serials (
                    id SERIAL PRIMARY KEY,
                    serial_key TEXT UNIQUE NOT NULL,
                    serial_hash TEXT UNIQUE NOT NULL,
                    machine_id TEXT NOT NULL,
                    user_name TEXT,
                    tier TEXT,
                    created_date TIMESTAMP NOT NULL,
                    expiry_date TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    last_check_time TIMESTAMP,
                    check_count INTEGER DEFAULT 0,
                    revoked_date TIMESTAMP,
                    revoked_reason TEXT,
                    created_by TEXT DEFAULT 'api',
                    encryption_type TEXT DEFAULT 'AES+XOR',
                    
                    -- 新增強制在線驗證欄位
                    force_online BOOLEAN DEFAULT FALSE,
                    validation_required BOOLEAN DEFAULT FALSE,
                    offline_disabled BOOLEAN DEFAULT FALSE,
                    server_validation_only BOOLEAN DEFAULT FALSE,
                    force_online_marker TEXT,
                    validation_token_required BOOLEAN DEFAULT FALSE,
                    last_validation_token TEXT,
                    validation_count INTEGER DEFAULT 0,
                    
                    -- 增強安全欄位
                    client_ip_history JSONB DEFAULT '[]',
                    last_client_ip TEXT,
                    security_flags JSONB DEFAULT '{}',
                    generator_version TEXT DEFAULT 'v6.0.0',
                    
                    -- 商業授權欄位
                    license_type TEXT DEFAULT 'standard',
                    max_concurrent_checks INTEGER DEFAULT 1,
                    api_rate_limit INTEGER DEFAULT 100,
                    
                    -- 系統追蹤欄位
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 黑名單表 - 增強版
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blacklist (
                    id SERIAL PRIMARY KEY,
                    machine_id TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    created_date TIMESTAMP NOT NULL,
                    created_by TEXT DEFAULT 'admin',
                    
                    -- 新增欄位
                    is_active BOOLEAN DEFAULT TRUE,
                    severity_level INTEGER DEFAULT 1,
                    auto_added BOOLEAN DEFAULT FALSE,
                    expiry_date TIMESTAMP,
                    notes TEXT,
                    ip_addresses JSONB DEFAULT '[]',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 驗證日誌表 - 增強版
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS validation_logs (
                    id SERIAL PRIMARY KEY,
                    serial_hash TEXT NOT NULL,
                    machine_id TEXT NOT NULL,
                    validation_time TIMESTAMP NOT NULL,
                    result TEXT NOT NULL,
                    client_ip TEXT,
                    user_agent TEXT,
                    
                    -- 新增強制在線驗證欄位
                    validation_token TEXT,
                    force_online_check BOOLEAN DEFAULT FALSE,
                    server_validation BOOLEAN DEFAULT FALSE,
                    validation_method TEXT DEFAULT 'standard',
                    response_time_ms INTEGER,
                    error_details TEXT,
                    
                    -- 安全追蹤
                    security_score INTEGER DEFAULT 100,
                    suspicious_activity BOOLEAN DEFAULT FALSE,
                    geo_location TEXT,
                    session_id TEXT
                )
            ''')
            
            # 新增：認證Token表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS auth_tokens (
                    id SERIAL PRIMARY KEY,
                    token_hash TEXT UNIQUE NOT NULL,
                    token_type TEXT DEFAULT 'validation',
                    created_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_by TEXT DEFAULT 'system',
                    usage_count INTEGER DEFAULT 0,
                    last_used_at TIMESTAMP,
                    client_info JSONB DEFAULT '{}',
                    permissions JSONB DEFAULT '{}'
                )
            ''')
            
            # 新增：系統配置表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_config (
                    id SERIAL PRIMARY KEY,
                    config_key TEXT UNIQUE NOT NULL,
                    config_value TEXT,
                    config_type TEXT DEFAULT 'string',
                    description TEXT,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # 新增：API使用統計表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS api_usage_stats (
                    id SERIAL PRIMARY KEY,
                    endpoint TEXT NOT NULL,
                    method TEXT NOT NULL,
                    client_ip TEXT,
                    user_agent TEXT,
                    response_code INTEGER,
                    response_time_ms INTEGER,
                    request_time TIMESTAMP NOT NULL,
                    request_size INTEGER DEFAULT 0,
                    response_size INTEGER DEFAULT 0,
                    error_message TEXT,
                    admin_key_used BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # 創建索引 - 優化查詢性能
            indexes = [
                'CREATE INDEX IF NOT EXISTS idx_serial_hash ON serials(serial_hash)',
                'CREATE INDEX IF NOT EXISTS idx_machine_id ON serials(machine_id)',
                'CREATE INDEX IF NOT EXISTS idx_serial_key ON serials(serial_key)',
                'CREATE INDEX IF NOT EXISTS idx_force_online ON serials(force_online)',
                'CREATE INDEX IF NOT EXISTS idx_validation_required ON serials(validation_required)',
                'CREATE INDEX IF NOT EXISTS idx_validation_time ON validation_logs(validation_time)',
                'CREATE INDEX IF NOT EXISTS idx_validation_result ON validation_logs(result)',
                'CREATE INDEX IF NOT EXISTS idx_force_online_check ON validation_logs(force_online_check)',
                'CREATE INDEX IF NOT EXISTS idx_blacklist_machine_id ON blacklist(machine_id)',
                'CREATE INDEX IF NOT EXISTS idx_blacklist_active ON blacklist(is_active)',
                'CREATE INDEX IF NOT EXISTS idx_auth_tokens_hash ON auth_tokens(token_hash)',
                'CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires ON auth_tokens(expires_at)',
                'CREATE INDEX IF NOT EXISTS idx_api_usage_endpoint ON api_usage_stats(endpoint)',
                'CREATE INDEX IF NOT EXISTS idx_api_usage_time ON api_usage_stats(request_time)',
                'CREATE INDEX IF NOT EXISTS idx_serials_created_at ON serials(created_at)',
                'CREATE INDEX IF NOT EXISTS idx_serials_expiry_date ON serials(expiry_date)'
            ]
            
            for index_sql in indexes:
                try:
                    cursor.execute(index_sql)
                except Exception as e:
                    print(f"⚠️ 索引創建警告: {e}")
            
            # 插入默認系統配置
            default_configs = [
                ('force_online_enabled', 'true', 'boolean', '是否啟用強制在線驗證'),
                ('token_lifetime_hours', '24', 'integer', 'Token有效期（小時）'),
                ('max_validation_rate', '100', 'integer', '每小時最大驗證次數'),
                ('security_level', 'high', 'string', '系統安全級別'),
                ('api_version', '6.0.0', 'string', 'API版本'),
                ('maintenance_mode', 'false', 'boolean', '維護模式')
            ]
            
            for config_key, config_value, config_type, description in default_configs:
                cursor.execute('''
                    INSERT INTO system_config (config_key, config_value, config_type, description)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (config_key) DO NOTHING
                ''', (config_key, config_value, config_type, description))
            
            conn.commit()
            conn.close()
            print("✅ 增強版 PostgreSQL 表創建完成")
            logger.info("✅ 增強版 PostgreSQL 資料庫初始化成功")
            
        except Exception as e:
            print(f"❌ PostgreSQL 初始化失敗: {e}")
            logger.error(f"❌ PostgreSQL 初始化失敗: {e}")
            raise
    
    def init_sqlite(self):
        """初始化 SQLite 資料庫（回退方案）- 增強版表結構"""
        try:
            print("🔧 創建增強版 SQLite 資料庫...")
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 增強版序號表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS serials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial_key TEXT UNIQUE NOT NULL,
                    serial_hash TEXT UNIQUE NOT NULL,
                    machine_id TEXT NOT NULL,
                    user_name TEXT,
                    tier TEXT,
                    created_date TEXT NOT NULL,
                    expiry_date TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    last_check_time TEXT,
                    check_count INTEGER DEFAULT 0,
                    revoked_date TEXT,
                    revoked_reason TEXT,
                    created_by TEXT DEFAULT 'api',
                    encryption_type TEXT DEFAULT 'AES+XOR',
                    
                    -- 強制在線驗證欄位
                    force_online BOOLEAN DEFAULT 0,
                    validation_required BOOLEAN DEFAULT 0,
                    offline_disabled BOOLEAN DEFAULT 0,
                    server_validation_only BOOLEAN DEFAULT 0,
                    force_online_marker TEXT,
                    validation_token_required BOOLEAN DEFAULT 0,
                    last_validation_token TEXT,
                    validation_count INTEGER DEFAULT 0,
                    
                    -- 增強安全欄位
                    client_ip_history TEXT DEFAULT '[]',
                    last_client_ip TEXT,
                    security_flags TEXT DEFAULT '{}',
                    generator_version TEXT DEFAULT 'v6.0.0',
                    
                    -- 商業授權欄位
                    license_type TEXT DEFAULT 'standard',
                    max_concurrent_checks INTEGER DEFAULT 1,
                    api_rate_limit INTEGER DEFAULT 100,
                    
                    -- 系統追蹤欄位
                    updated_at TEXT,
                    created_at TEXT
                )
            ''')
            
            # 其他表結構（簡化版）
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    machine_id TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    created_date TEXT NOT NULL,
                    created_by TEXT DEFAULT 'admin',
                    is_active BOOLEAN DEFAULT 1,
                    severity_level INTEGER DEFAULT 1,
                    auto_added BOOLEAN DEFAULT 0,
                    expiry_date TEXT,
                    notes TEXT,
                    updated_at TEXT
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
                    validation_token TEXT,
                    force_online_check BOOLEAN DEFAULT 0,
                    server_validation BOOLEAN DEFAULT 0,
                    validation_method TEXT DEFAULT 'standard',
                    response_time_ms INTEGER,
                    error_details TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS auth_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_hash TEXT UNIQUE NOT NULL,
                    token_type TEXT DEFAULT 'validation',
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_by TEXT DEFAULT 'system',
                    usage_count INTEGER DEFAULT 0,
                    last_used_at TEXT
                )
            ''')
            
            # 創建索引
            indexes = [
                'CREATE INDEX IF NOT EXISTS idx_serial_hash ON serials(serial_hash)',
                'CREATE INDEX IF NOT EXISTS idx_machine_id ON serials(machine_id)',
                'CREATE INDEX IF NOT EXISTS idx_serial_key ON serials(serial_key)',
                'CREATE INDEX IF NOT EXISTS idx_force_online ON serials(force_online)',
                'CREATE INDEX IF NOT EXISTS idx_validation_time ON validation_logs(validation_time)'
            ]
            
            for index_sql in indexes:
                try:
                    cursor.execute(index_sql)
                except Exception as e:
                    print(f"⚠️ SQLite索引創建警告: {e}")
            
            conn.commit()
            conn.close()
            print("✅ 增強版 SQLite 資料庫創建完成")
            logger.info("✅ 增強版 SQLite 資料庫初始化成功")
            
        except Exception as e:
            print(f"❌ SQLite 初始化失敗: {e}")
            logger.error(f"❌ SQLite 初始化失敗: {e}")
            raise
    
    def generate_validation_token(self, request_type: str = "validation") -> Dict[str, Any]:
        """生成驗證Token"""
        try:
            # 生成安全的隨機Token
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            created_at = datetime.now()
            expires_at = created_at + self.token_lifetime
            
            # 存儲到資料庫
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    INSERT INTO auth_tokens 
                    (token_hash, token_type, created_at, expires_at, created_by)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (token_hash, request_type, created_at, expires_at, 'api'))
            else:
                cursor.execute('''
                    INSERT INTO auth_tokens 
                    (token_hash, token_type, created_at, expires_at, created_by)
                    VALUES (?, ?, ?, ?, ?)
                ''', (token_hash, request_type, self._format_datetime(created_at), 
                      self._format_datetime(expires_at), 'api'))
            
            conn.commit()
            conn.close()
            
            # 內存緩存
            self.active_tokens[token] = {
                'expires_at': expires_at,
                'type': request_type,
                'created_at': created_at
            }
            
            logger.info(f"✅ 驗證Token生成成功: {token_hash[:8]}...")
            
            return {
                'token': token,
                'expires_at': expires_at.isoformat(),
                'token_type': request_type,
                'lifetime_hours': self.token_lifetime.total_seconds() / 3600
            }
            
        except Exception as e:
            logger.error(f"❌ 生成驗證Token失敗: {e}")
            return None
    
    def validate_token(self, token: str) -> bool:
        """驗證Token有效性"""
        try:
            current_time = datetime.now()
            
            # 檢查內存緩存
            if token in self.active_tokens:
                token_info = self.active_tokens[token]
                if current_time < token_info['expires_at']:
                    return True
                else:
                    # Token過期，從緩存中移除
                    del self.active_tokens[token]
            
            # 檢查資料庫
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    SELECT expires_at, is_active, token_type 
                    FROM auth_tokens 
                    WHERE token_hash = %s AND is_active = TRUE
                ''', (token_hash,))
            else:
                cursor.execute('''
                    SELECT expires_at, is_active, token_type 
                    FROM auth_tokens 
                    WHERE token_hash = ? AND is_active = 1
                ''', (token_hash,))
            
            result = cursor.fetchone()
            
            if result:
                expires_at_str, is_active, token_type = result
                expires_at = self._parse_datetime(expires_at_str)
                
                if current_time < expires_at and is_active:
                    # 更新使用次數
                    if self.use_postgresql:
                        cursor.execute('''
                            UPDATE auth_tokens 
                            SET usage_count = usage_count + 1, last_used_at = %s
                            WHERE token_hash = %s
                        ''', (current_time, token_hash))
                    else:
                        cursor.execute('''
                            UPDATE auth_tokens 
                            SET usage_count = usage_count + 1, last_used_at = ?
                            WHERE token_hash = ?
                        ''', (self._format_datetime(current_time), token_hash))
                    
                    conn.commit()
                    conn.close()
                    
                    # 更新內存緩存
                    self.active_tokens[token] = {
                        'expires_at': expires_at,
                        'type': token_type,
                        'created_at': current_time
                    }
                    
                    return True
            
            conn.close()
            return False
            
        except Exception as e:
            logger.error(f"❌ Token驗證失敗: {e}")
            return False
    
    def cleanup_expired_tokens(self):
        """清理過期Token"""
        try:
            current_time = datetime.now()
            
            # 清理內存緩存
            expired_tokens = [token for token, info in self.active_tokens.items() 
                            if current_time >= info['expires_at']]
            for token in expired_tokens:
                del self.active_tokens[token]
            
            # 清理資料庫
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    UPDATE auth_tokens 
                    SET is_active = FALSE 
                    WHERE expires_at < %s AND is_active = TRUE
                ''', (current_time,))
            else:
                cursor.execute('''
                    UPDATE auth_tokens 
                    SET is_active = 0 
                    WHERE expires_at < ? AND is_active = 1
                ''', (self._format_datetime(current_time),))
            
            cleaned_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if cleaned_count > 0:
                logger.info(f"🧹 清理過期Token: {cleaned_count}個")
            
        except Exception as e:
            logger.error(f"❌ 清理過期Token失敗: {e}")
    
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
        if dt_str is None:
            return datetime.now()
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    
    def register_serial_enhanced(self, serial_key: str, machine_id: str, tier: str, 
                               days: int, user_name: str = "使用者", 
                               encryption_type: str = "AES+XOR+ForceOnline",
                               force_online: bool = True) -> bool:
        """增強版序號註冊 - 支援強制在線驗證"""
        try:
            serial_hash = self.hash_serial(serial_key)
            current_time = datetime.now()
            expiry_date = current_time + timedelta(days=days)
            
            # 解析強制在線標記
            force_online_marker = "FORCE_ONLINE_V6" if force_online else None
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    INSERT INTO serials 
                    (serial_key, serial_hash, machine_id, user_name, tier, 
                     created_date, expiry_date, created_by, encryption_type,
                     force_online, validation_required, offline_disabled, 
                     server_validation_only, force_online_marker, generator_version,
                     created_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (serial_key) DO UPDATE SET
                    machine_id = EXCLUDED.machine_id,
                    user_name = EXCLUDED.user_name,
                    tier = EXCLUDED.tier,
                    expiry_date = EXCLUDED.expiry_date,
                    encryption_type = EXCLUDED.encryption_type,
                    force_online = EXCLUDED.force_online,
                    validation_required = EXCLUDED.validation_required,
                    offline_disabled = EXCLUDED.offline_disabled,
                    server_validation_only = EXCLUDED.server_validation_only,
                    force_online_marker = EXCLUDED.force_online_marker,
                    updated_at = EXCLUDED.updated_at
                ''', (serial_key, serial_hash, machine_id, user_name, tier, 
                      current_time, expiry_date, 'api_enhanced', encryption_type,
                      force_online, force_online, force_online, force_online, 
                      force_online_marker, 'v6.0.0', current_time, current_time))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO serials 
                    (serial_key, serial_hash, machine_id, user_name, tier, 
                     created_date, expiry_date, created_by, encryption_type,
                     force_online, validation_required, offline_disabled, 
                     server_validation_only, force_online_marker, generator_version,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (serial_key, serial_hash, machine_id, user_name, tier, 
                      self._format_datetime(current_time), self._format_datetime(expiry_date), 
                      'api_enhanced', encryption_type, 1 if force_online else 0, 
                      1 if force_online else 0, 1 if force_online else 0, 
                      1 if force_online else 0, force_online_marker, 'v6.0.0',
                      self._format_datetime(current_time), self._format_datetime(current_time)))
            
            conn.commit()
            conn.close()
            
            logger.info(f"✅ 增強版序號註冊成功: {serial_hash[:8]}... (強制在線: {force_online})")
            return True
            
        except Exception as e:
            logger.error(f"❌ 增強版序號註冊失敗: {e}")
            return False
    
    def validate_serial_enhanced(self, serial_key: str, machine_id: str, 
                               validation_token: str = None,
                               client_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """增強版序號驗證 - 支援強制在線驗證"""
        try:
            start_time = time.time()
            serial_hash = self.hash_serial(serial_key)
            current_time = datetime.now()
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # 檢查黑名單
            if self.use_postgresql:
                cursor.execute('''
                    SELECT reason, severity_level 
                    FROM blacklist 
                    WHERE machine_id = %s AND is_active = TRUE
                ''', (machine_id,))
            else:
                cursor.execute('''
                    SELECT reason, severity_level 
                    FROM blacklist 
                    WHERE machine_id = ? AND is_active = 1
                ''', (machine_id,))
            
            blacklist_result = cursor.fetchone()
            if blacklist_result:
                response_time = int((time.time() - start_time) * 1000)
                self._log_validation_enhanced(cursor, serial_hash, machine_id, current_time, 
                                            'BLACKLISTED', client_ip, validation_token, 
                                            True, True, response_time, f"黑名單: {blacklist_result[0]}")
                conn.commit()
                conn.close()
                return {
                    'valid': False,
                    'error': f'機器在黑名單中: {blacklist_result[0]}',
                    'blacklisted': True,
                    'severity_level': blacklist_result[1] if len(blacklist_result) > 1 else 1,
                    'requires_online': True
                }
            
            # 檢查序號
            if self.use_postgresql:
                cursor.execute('''
                    SELECT machine_id, expiry_date, is_active, tier, user_name, check_count,
                           force_online, validation_required, offline_disabled, 
                           server_validation_only, force_online_marker, validation_count,
                           last_validation_token, generator_version
                    FROM serials WHERE serial_hash = %s
                ''', (serial_hash,))
            else:
                cursor.execute('''
                    SELECT machine_id, expiry_date, is_active, tier, user_name, check_count,
                           force_online, validation_required, offline_disabled, 
                           server_validation_only, force_online_marker, validation_count,
                           last_validation_token, generator_version
                    FROM serials WHERE serial_hash = ?
                ''', (serial_hash,))
            
            result = cursor.fetchone()
            
            if not result:
                response_time = int((time.time() - start_time) * 1000)
                self._log_validation_enhanced(cursor, serial_hash, machine_id, current_time, 
                                            'NOT_FOUND', client_ip, validation_token, 
                                            False, False, response_time, "序號不存在")
                conn.commit()
                conn.close()
                return {
                    'valid': False, 
                    'error': '序號不存在',
                    'requires_online': True
                }
            
            (stored_machine_id, expiry_date, is_active, tier, user_name, check_count,
             force_online, validation_required, offline_disabled, server_validation_only, 
             force_online_marker, validation_count, last_validation_token, generator_version) = result
            
            # 強制在線驗證檢查
            if force_online or validation_required:
                if not validation_token:
                    response_time = int((time.time() - start_time) * 1000)
                    self._log_validation_enhanced(cursor, serial_hash, machine_id, current_time, 
                                                'TOKEN_REQUIRED', client_ip, None, 
                                                True, True, response_time, "需要驗證Token")
                    conn.commit()
                    conn.close()
                    return {
                        'valid': False,
                        'error': '需要驗證Token進行強制在線驗證',
                        'requires_online': True,
                        'force_online': True,
                        'validation_required': True
                    }
                
                # 驗證Token
                if not self.validate_token(validation_token):
                    response_time = int((time.time() - start_time) * 1000)
                    self._log_validation_enhanced(cursor, serial_hash, machine_id, current_time, 
                                                'INVALID_TOKEN', client_ip, validation_token, 
                                                True, True, response_time, "無效的驗證Token")
                    conn.commit()
                    conn.close()
                    return {
                        'valid': False,
                        'error': '無效的驗證Token',
                        'requires_online': True,
                        'force_online': True
                    }
            
            # 檢查機器ID綁定
            if stored_machine_id != machine_id:
                response_time = int((time.time() - start_time) * 1000)
                self._log_validation_enhanced(cursor, serial_hash, machine_id, current_time, 
                                            'MACHINE_MISMATCH', client_ip, validation_token, 
                                            bool(force_online), bool(server_validation_only), 
                                            response_time, "機器ID不匹配")
                conn.commit()
                conn.close()
                return {
                    'valid': False, 
                    'error': '序號已綁定到其他機器',
                    'requires_online': bool(force_online)
                }
            
            # 檢查是否被停用
            if not is_active:
                response_time = int((time.time() - start_time) * 1000)
                self._log_validation_enhanced(cursor, serial_hash, machine_id, current_time, 
                                            'REVOKED', client_ip, validation_token, 
                                            bool(force_online), bool(server_validation_only), 
                                            response_time, "序號已停用")
                conn.commit()
                conn.close()
                return {
                    'valid': False, 
                    'error': '序號已被停用',
                    'requires_online': bool(force_online)
                }
            
            # 檢查過期時間
            expiry_dt = self._parse_datetime(expiry_date)
            if current_time > expiry_dt:
                response_time = int((time.time() - start_time) * 1000)
                self._log_validation_enhanced(cursor, serial_hash, machine_id, current_time, 
                                            'EXPIRED', client_ip, validation_token, 
                                            bool(force_online), bool(server_validation_only), 
                                            response_time, "序號已過期")
                conn.commit()
                conn.close()
                return {
                    'valid': False, 
                    'error': '序號已過期', 
                    'expired': True,
                    'requires_online': bool(force_online)
                }
            
            # 更新檢查時間和次數
            new_check_count = (check_count or 0) + 1
            new_validation_count = (validation_count or 0) + 1
            
            if self.use_postgresql:
                cursor.execute('''
                    UPDATE serials 
                    SET last_check_time = %s, check_count = %s, validation_count = %s,
                        last_validation_token = %s, last_client_ip = %s, updated_at = %s
                    WHERE serial_hash = %s
                ''', (current_time, new_check_count, new_validation_count,
                      validation_token, client_ip, current_time, serial_hash))
            else:
                cursor.execute('''
                    UPDATE serials 
                    SET last_check_time = ?, check_count = ?, validation_count = ?,
                        last_validation_token = ?, last_client_ip = ?, updated_at = ?
                    WHERE serial_hash = ?
                ''', (self._format_datetime(current_time), new_check_count, new_validation_count,
                      validation_token, client_ip, self._format_datetime(current_time), serial_hash))
            
            response_time = int((time.time() - start_time) * 1000)
            self._log_validation_enhanced(cursor, serial_hash, machine_id, current_time, 
                                        'VALID', client_ip, validation_token, 
                                        bool(force_online), bool(server_validation_only), 
                                        response_time, None)
            
            conn.commit()
            conn.close()
            
            remaining_days = max(0, (expiry_dt - current_time).days)
            
            return {
                'valid': True,
                'tier': tier,
                'user_name': user_name,
                'expiry_date': self._format_datetime(expiry_dt),
                'remaining_days': remaining_days,
                'check_count': new_check_count,
                'validation_count': new_validation_count,
                'force_online': bool(force_online),
                'validation_required': bool(validation_required),
                'offline_disabled': bool(offline_disabled),
                'server_validation_only': bool(server_validation_only),
                'generator_version': generator_version or 'v6.0.0',
                'response_time_ms': response_time
            }
            
        except Exception as e:
            logger.error(f"❌ 增強版驗證過程錯誤: {e}")
            return {
                'valid': False, 
                'error': f'驗證過程錯誤: {str(e)}',
                'requires_online': True
            }
    
    def _log_validation_enhanced(self, cursor, serial_hash: str, machine_id: str, 
                               validation_time: datetime, result: str, client_ip: str,
                               validation_token: str = None, force_online_check: bool = False,
                               server_validation: bool = False, response_time_ms: int = 0,
                               error_details: str = None):
        """增強版驗證日誌記錄"""
        try:
            if self.use_postgresql:
                cursor.execute('''
                    INSERT INTO validation_logs 
                    (serial_hash, machine_id, validation_time, result, client_ip,
                     validation_token, force_online_check, server_validation, 
                     validation_method, response_time_ms, error_details)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (serial_hash, machine_id, validation_time, result, client_ip,
                      validation_token, force_online_check, server_validation, 
                      'enhanced_v6', response_time_ms, error_details))
            else:
                cursor.execute('''
                    INSERT INTO validation_logs 
                    (serial_hash, machine_id, validation_time, result, client_ip,
                     validation_token, force_online_check, server_validation, 
                     validation_method, response_time_ms, error_details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (serial_hash, machine_id, self._format_datetime(validation_time), 
                      result, client_ip, validation_token, 
                      1 if force_online_check else 0, 1 if server_validation else 0, 
                      'enhanced_v6', response_time_ms, error_details))
        except Exception as e:
            logger.error(f"❌ 記錄增強版驗證日誌失敗: {e}")
    
    def get_enhanced_statistics(self) -> Dict[str, Any]:
        """獲取增強版統計資訊"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            stats = {}
            
            # 基礎統計
            cursor.execute('SELECT COUNT(*) FROM serials')
            stats['total_serials'] = cursor.fetchone()[0]
            
            if self.use_postgresql:
                cursor.execute('SELECT COUNT(*) FROM serials WHERE is_active = TRUE')
                stats['active_serials'] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM serials WHERE force_online = TRUE')
                stats['force_online_serials'] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM serials WHERE validation_required = TRUE')
                stats['validation_required_serials'] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM blacklist WHERE is_active = TRUE')
                stats['active_blacklist'] = cursor.fetchone()[0]
                
                # 今日統計
                cursor.execute("SELECT COUNT(*) FROM validation_logs WHERE DATE(validation_time) = CURRENT_DATE")
                stats['today_validations'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM validation_logs WHERE DATE(validation_time) = CURRENT_DATE AND force_online_check = TRUE")
                stats['today_force_online_validations'] = cursor.fetchone()[0]
                
                # Token統計
                cursor.execute('SELECT COUNT(*) FROM auth_tokens WHERE is_active = TRUE')
                stats['active_tokens'] = cursor.fetchone()[0]
                
            else:
                cursor.execute('SELECT COUNT(*) FROM serials WHERE is_active = 1')
                stats['active_serials'] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM serials WHERE force_online = 1')
                stats['force_online_serials'] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM serials WHERE validation_required = 1')
                stats['validation_required_serials'] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM blacklist WHERE is_active = 1')
                stats['active_blacklist'] = cursor.fetchone()[0]
                
                today = datetime.now().date().isoformat()
                cursor.execute('SELECT COUNT(*) FROM validation_logs WHERE DATE(validation_time) = ?', (today,))
                stats['today_validations'] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM validation_logs WHERE DATE(validation_time) = ? AND force_online_check = 1', (today,))
                stats['today_force_online_validations'] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM auth_tokens WHERE is_active = 1')
                stats['active_tokens'] = cursor.fetchone()[0]
            
            stats['revoked_serials'] = stats['total_serials'] - stats['active_serials']
            stats['force_online_percentage'] = round((stats['force_online_serials'] / max(1, stats['total_serials'])) * 100, 2)
            
            # 系統資訊
            stats['database_type'] = 'PostgreSQL' if self.use_postgresql else 'SQLite'
            stats['database_url_found'] = bool(self.database_url)
            stats['psycopg2_available'] = PSYCOPG2_AVAILABLE
            stats['api_version'] = '6.0.0'
            stats['force_online_enabled'] = True
            stats['active_tokens_memory'] = len(self.active_tokens)
            
            conn.close()
            return stats
            
        except Exception as e:
            logger.error(f"❌ 獲取增強版統計失敗: {e}")
            return {
                'database_type': 'PostgreSQL' if self.use_postgresql else 'SQLite',
                'database_url_found': bool(self.database_url),
                'psycopg2_available': PSYCOPG2_AVAILABLE,
                'api_version': '6.0.0',
                'error': str(e)
            }
    
    # 向前兼容的方法
    def register_serial(self, serial_key: str, machine_id: str, tier: str, 
                       days: int, user_name: str = "使用者", 
                       encryption_type: str = "AES+XOR") -> bool:
        """向前兼容的序號註冊方法"""
        return self.register_serial_enhanced(serial_key, machine_id, tier, days, 
                                           user_name, encryption_type, force_online=False)
    
    def validate_serial(self, serial_key: str, machine_id: str, 
                       client_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """向前兼容的序號驗證方法"""
        return self.validate_serial_enhanced(serial_key, machine_id, None, client_ip)
    
    def get_statistics(self) -> Dict[str, Any]:
        """向前兼容的統計方法"""
        return self.get_enhanced_statistics()

# 初始化增強版資料庫管理器
try:
    print("🚀 初始化增強版資料庫管理器...")
    db_manager = EnhancedDatabaseManager()
    print("✅ 增強版資料庫管理器初始化完成")
    logger.info("✅ 增強版資料庫管理器初始化成功")
    
    # 定期清理過期Token
    import threading
    def periodic_cleanup():
        while True:
            time.sleep(3600)  # 每小時清理一次
            db_manager.cleanup_expired_tokens()
    
    cleanup_thread = threading.Thread(target=periodic_cleanup, daemon=True)
    cleanup_thread.start()
    
except Exception as e:
    print(f"❌ 增強版資料庫管理器初始化失敗: {e}")
    logger.error(f"❌ 增強版資料庫管理器初始化失敗: {e}")
    sys.exit(1)

# ============================================================================
# 增強版 API 路由 - 支援強制在線驗證
# ============================================================================

@app.route('/')
def home():
    """增強版首頁"""
    stats = db_manager.get_enhanced_statistics()
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BOSS檢測器 Railway 增強版驗證伺服器 v6.0.0</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial; margin: 40px; background: #f5f5f5; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            .header { text-align: center; margin-bottom: 30px; }
            .status { padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 5px solid; }
            .success { background: #d4edda; color: #155724; border-color: #28a745; }
            .info { background: #d1ecf1; color: #0c5460; border-color: #17a2b8; }
            .warning { background: #fff3cd; color: #856404; border-color: #ffc107; }
            .enhanced { background: #e7f3ff; color: #0066cc; border-color: #007bff; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f8f9fa; font-weight: bold; }
            .db-type { font-weight: bold; color: #007bff; }
            .metric { font-weight: bold; color: #28a745; }
            .api-section { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
            .new-feature { color: #dc3545; font-weight: bold; }
            .version-badge { background: #007bff; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ BOSS檢測器 Railway 增強版驗證伺服器</h1>
                <span class="version-badge">v6.0.0 強制在線增強版</span>
            </div>
            
            <div class="status success">
                ✅ 伺服器運行正常 - {{ current_time }}
            </div>
            
            <div class="status enhanced">
                🔒 <strong>強制在線驗證已啟用</strong> - 支援Token認證與離線保護
            </div>
            
            {% if stats.database_type == 'PostgreSQL' %}
            <div class="status success">
                🐘 <span class="db-type">PostgreSQL</span> 資料庫已連接 - 數據永久保存
            </div>
            {% else %}
            <div class="status warning">
                🗄️ <span class="db-type">SQLite</span> 資料庫 - 調試資訊：
                <br>DATABASE_URL 找到: {{ '是' if stats.database_url_found else '否' }}
                <br>psycopg2 可用: {{ '是' if stats.psycopg2_available else '否' }}
            </div>
            {% endif %}
            
            <h2>📊 增強版伺服器狀態</h2>
            <table>
                <tr><th>系統資訊</th><th>狀態</th></tr>
                <tr><td>API版本</td><td class="metric">{{ stats.api_version }}</td></tr>
                <tr><td>部署平台</td><td>Railway.app</td></tr>
                <tr><td>資料庫類型</td><td class="db-type">{{ stats.database_type }}</td></tr>
                <tr><td>強制在線驗證</td><td class="new-feature">{{ '✅ 已啟用' if stats.force_online_enabled else '❌ 未啟用' }}</td></tr>
                <tr><td>DATABASE_URL 存在</td><td>{{ '✅ 是' if stats.database_url_found else '❌ 否' }}</td></tr>
                <tr><td>psycopg2 可用</td><td>{{ '✅ 是' if stats.psycopg2_available else '❌ 否' }}</td></tr>
            </table>
            
            <h2>📈 序號統計</h2>
            <table>
                <tr><th>序號類型</th><th>數量</th><th>比例</th></tr>
                <tr><td>總序號數</td><td class="metric">{{ stats.total_serials }}</td><td>100%</td></tr>
                <tr><td>活躍序號</td><td class="metric">{{ stats.active_serials }}</td><td>{{ "%.1f"|format((stats.active_serials / (stats.total_serials or 1)) * 100) }}%</td></tr>
                <tr><td>停用序號</td><td>{{ stats.revoked_serials }}</td><td>{{ "%.1f"|format((stats.revoked_serials / (stats.total_serials or 1)) * 100) }}%</td></tr>
                <tr><td class="new-feature">強制在線序號</td><td class="metric">{{ stats.force_online_serials }}</td><td class="new-feature">{{ stats.force_online_percentage }}%</td></tr>
                <tr><td class="new-feature">需驗證序號</td><td class="metric">{{ stats.validation_required_serials }}</td><td>{{ "%.1f"|format((stats.validation_required_serials / (stats.total_serials or 1)) * 100) }}%</td></tr>
            </table>
            
            <h2>🔐 安全統計</h2>
            <table>
                <tr><th>安全項目</th><th>數量</th></tr>
                <tr><td>活躍黑名單</td><td class="metric">{{ stats.active_blacklist }}</td></tr>
                <tr><td class="new-feature">活躍Token</td><td class="metric">{{ stats.active_tokens }}</td></tr>
                <tr><td class="new-feature">內存Token</td><td class="metric">{{ stats.active_tokens_memory }}</td></tr>
                <tr><td>今日總驗證</td><td class="metric">{{ stats.today_validations }}</td></tr>
                <tr><td class="new-feature">今日強制在線驗證</td><td class="metric">{{ stats.today_force_online_validations }}</td></tr>
            </table>
            
            <div class="api-section">
                <h2>🔗 增強版 API 端點</h2>
                <h3>🆕 新增強制在線驗證端點：</h3>
                <p>
                    <strong class="new-feature">Token認證:</strong> POST /api/auth/token<br>
                    <strong class="new-feature">強制在線註冊:</strong> POST /api/register/enhanced<br>
                    <strong class="new-feature">強制在線註冊 (別名):</strong> POST /api/register/force<br>
                    <strong class="new-feature">強制在線驗證:</strong> POST /api/validate/enhanced<br>
                    <strong class="new-feature">強制在線驗證 (別名):</strong> POST /api/validate/force<br>
                </p>
                
                <h3>📡 標準API端點：</h3>
                <p>
                    <strong>驗證序號:</strong> POST /api/validate<br>
                    <strong>註冊序號:</strong> POST /api/register<br>
                    <strong>另一註冊端點:</strong> POST /api/add<br>
                    <strong>停用序號:</strong> POST /api/revoke<br>
                    <strong>恢復序號:</strong> POST /api/restore<br>
                    <strong>添加黑名單:</strong> POST /api/blacklist<br>
                    <strong>移除黑名單:</strong> POST /api/blacklist/remove<br>
                    <strong>檢查黑名單:</strong> POST /api/blacklist/check<br>
                    <strong>檢查序號狀態:</strong> POST /api/serial/status<br>
                    <strong>獲取統計:</strong> GET /api/stats<br>
                    <strong>健康檢查:</strong> GET /api/health<br>
                </p>
            </div>
            
            <div class="status info">
                <strong>🔒 強制在線驗證特性：</strong><br>
                • Token認證機制確保只有授權的客戶端能夠驗證<br>
                • 離線保護防止序號被離線破解<br>
                • 實時服務器驗證，可遠端控制序號狀態<br>
                • 適合商業授權和防盜版需求
            </div>
        </div>
    </body>
    </html>
    ''', current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), stats=stats)

@app.route('/api/health')
def health_check():
    """增強版健康檢查"""
    stats = db_manager.get_enhanced_statistics()
    return jsonify({
        'status': 'healthy',
        'server': 'BOSS檢測器 Railway 增強版驗證伺服器',
        'version': '6.0.0',
        'api_version': '6.0.0',
        'timestamp': datetime.now().isoformat(),
        'database': stats.get('database_type', 'Unknown'),
        'force_online_enabled': True,
        'features': {
            'token_authentication': True,
            'force_online_validation': True,
            'offline_protection': True,
            'enhanced_logging': True,
            'blacklist_management': True,
            'real_time_control': True
        },
        'debug_info': {
            'database_url_found': stats.get('database_url_found', False),
            'psycopg2_available': stats.get('psycopg2_available', False),
            'active_tokens': stats.get('active_tokens', 0),
            'active_tokens_memory': stats.get('active_tokens_memory', 0)
        },
        'stats': stats
    })

# ============================================================================
# 新增：強制在線驗證專用API端點
# ============================================================================

@app.route('/api/auth/token', methods=['POST'])
def get_auth_token():
    """獲取認證Token - 強制在線驗證必需"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '無效的請求資料'}), 400
        
        admin_key = data.get('admin_key')
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        # 檢查驗證Token（如果是強制在線註冊）
        validation_token = data.get('validation_token')
        force_online = data.get('force_online', True)
        
        if force_online and validation_token:
            if not db_manager.validate_token(validation_token):
                return jsonify({'success': False, 'error': '無效的驗證Token'}), 401
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        tier = data.get('tier', 'trial')
        days = data.get('days', 7)
        user_name = data.get('user_name', '使用者')
        encryption_type = data.get('encryption_type', 'AES+XOR+ForceOnline')
        
        if not serial_key or not machine_id:
            return jsonify({'success': False, 'error': '缺少必要參數'}), 400
        
        success = db_manager.register_serial_enhanced(
            serial_key, machine_id, tier, days, user_name, encryption_type, force_online
        )
        
        # 生成新的Token給客戶端（如果需要）
        new_token_info = None
        if success and force_online:
            new_token_info = db_manager.generate_validation_token('validation')
        
        response_data = {
            'success': success,
            'registered': success,
            'force_registered': success and force_online,
            'message': '強制在線序號註冊成功' if success else '序號註冊失敗',
            'force_online': force_online,
            'validation_required': force_online
        }
        
        if new_token_info:
            response_data['new_token'] = new_token_info['token']
            response_data['token_expires'] = new_token_info['expires_at']
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"❌ 增強版註冊API錯誤: {e}")
        return jsonify({'success': False, 'error': f'註冊失敗: {str(e)}'}), 500

@app.route('/api/validate/enhanced', methods=['POST'])
@app.route('/api/validate/force', methods=['POST'])
def validate_serial_enhanced():
    """增強版序號驗證 - 支援強制在線驗證"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'error': '無效的請求資料'}), 400
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        validation_token = data.get('validation_token')
        force_online = data.get('force_online', True)
        
        if not serial_key or not machine_id:
            return jsonify({'valid': False, 'error': '缺少必要參數'}), 400
        
        # 強制在線驗證需要Token
        if force_online and not validation_token:
            return jsonify({
                'valid': False, 
                'error': '強制在線驗證需要驗證Token',
                'requires_online': True,
                'force_online': True
            }), 401
        
        client_ip = request.remote_addr
        result = db_manager.validate_serial_enhanced(serial_key, machine_id, validation_token, client_ip)
        
        # 生成新Token（如果驗證成功且是強制在線模式）
        if result.get('valid', False) and force_online:
            new_token_info = db_manager.generate_validation_token('validation')
            if new_token_info:
                result['new_token'] = new_token_info['token']
                result['token_expires'] = new_token_info['expires_at']
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"❌ 增強版驗證API錯誤: {e}")
        return jsonify({'valid': False, 'error': f'驗證失敗: {str(e)}'}), 500

# ============================================================================
# 向前兼容的標準API端點
# ============================================================================

@app.route('/api/validate', methods=['POST'])
def validate_serial():
    """標準序號驗證"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'error': '無效的請求資料'}), 400
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        
        if not serial_key or not machine_id:
            return jsonify({'valid': False, 'error': '缺少必要參數'}), 400
        
        client_ip = request.remote_addr
        result = db_manager.validate_serial(serial_key, machine_id, client_ip)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"❌ 標準驗證API錯誤: {e}")
        return jsonify({'valid': False, 'error': f'驗證失敗: {str(e)}'}), 500

@app.route('/api/register', methods=['POST'])
@app.route('/api/add', methods=['POST'])
def register_serial():
    """標準序號註冊"""
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
            'registered': success,
            'message': '序號註冊成功' if success else '序號註冊失敗'
        })
        
    except Exception as e:
        logger.error(f"❌ 標準註冊API錯誤: {e}")
        return jsonify({'success': False, 'error': f'註冊失敗: {str(e)}'}), 500

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
        
        # 實現停用邏輯
        try:
            serial_hash = db_manager.hash_serial(serial_key)
            revoked_date = datetime.now()
            
            conn = db_manager.get_connection()
            cursor = conn.cursor()
            
            if db_manager.use_postgresql:
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = FALSE, revoked_date = %s, revoked_reason = %s, updated_at = %s
                    WHERE serial_hash = %s
                ''', (revoked_date, reason, revoked_date, serial_hash))
            else:
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = 0, revoked_date = ?, revoked_reason = ?, updated_at = ?
                    WHERE serial_hash = ?
                ''', (db_manager._format_datetime(revoked_date), reason, 
                      db_manager._format_datetime(revoked_date), serial_hash))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            if success:
                logger.info(f"✅ 序號停用成功: {serial_hash[:8]}...")
            
            return jsonify({
                'success': success,
                'message': '序號停用成功' if success else '序號停用失敗'
            })
            
        except Exception as revoke_error:
            logger.error(f"❌ 停用序號失敗: {revoke_error}")
            return jsonify({'success': False, 'error': f'停用失敗: {str(revoke_error)}'}), 500
            
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
        
        # 實現恢復邏輯
        try:
            serial_hash = db_manager.hash_serial(serial_key)
            updated_date = datetime.now()
            
            conn = db_manager.get_connection()
            cursor = conn.cursor()
            
            if db_manager.use_postgresql:
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = TRUE, revoked_date = NULL, revoked_reason = NULL, updated_at = %s
                    WHERE serial_hash = %s
                ''', (updated_date, serial_hash))
            else:
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = 1, revoked_date = NULL, revoked_reason = NULL, updated_at = ?
                    WHERE serial_hash = ?
                ''', (db_manager._format_datetime(updated_date), serial_hash))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            if success:
                logger.info(f"✅ 序號恢復成功: {serial_hash[:8]}...")
            
            return jsonify({
                'success': success,
                'message': '序號恢復成功' if success else '序號恢復失敗'
            })
            
        except Exception as restore_error:
            logger.error(f"❌ 恢復序號失敗: {restore_error}")
            return jsonify({'success': False, 'error': f'恢復失敗: {str(restore_error)}'}), 500
            
    except Exception as e:
        logger.error(f"❌ 恢復API錯誤: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

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
        severity_level = data.get('severity_level', 1)
        
        if not machine_id:
            return jsonify({'success': False, 'error': '缺少機器ID'}), 400
        
        # 實現添加黑名單邏輯
        try:
            created_date = datetime.now()
            
            conn = db_manager.get_connection()
            cursor = conn.cursor()
            
            if db_manager.use_postgresql:
                cursor.execute('''
                    INSERT INTO blacklist 
                    (machine_id, reason, created_date, severity_level, is_active, updated_at)
                    VALUES (%s, %s, %s, %s, TRUE, %s)
                    ON CONFLICT (machine_id) DO UPDATE SET
                    reason = EXCLUDED.reason,
                    severity_level = EXCLUDED.severity_level,
                    is_active = TRUE,
                    updated_at = EXCLUDED.updated_at
                ''', (machine_id, reason, created_date, severity_level, created_date))
                
                # 同時停用該機器的所有序號
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = FALSE, revoked_date = %s, revoked_reason = %s, updated_at = %s
                    WHERE machine_id = %s AND is_active = TRUE
                ''', (created_date, f"黑名單自動停用: {reason}", created_date, machine_id))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO blacklist 
                    (machine_id, reason, created_date, severity_level, is_active, updated_at)
                    VALUES (?, ?, ?, ?, 1, ?)
                ''', (machine_id, reason, db_manager._format_datetime(created_date), 
                      severity_level, db_manager._format_datetime(created_date)))
                
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = 0, revoked_date = ?, revoked_reason = ?, updated_at = ?
                    WHERE machine_id = ? AND is_active = 1
                ''', (db_manager._format_datetime(created_date), f"黑名單自動停用: {reason}", 
                      db_manager._format_datetime(created_date), machine_id))
            
            conn.commit()
            conn.close()
            logger.info(f"✅ 黑名單添加成功: {machine_id}")
            
            return jsonify({
                'success': True,
                'message': '黑名單添加成功'
            })
            
        except Exception as blacklist_error:
            logger.error(f"❌ 添加黑名單失敗: {blacklist_error}")
            return jsonify({'success': False, 'error': f'添加失敗: {str(blacklist_error)}'}), 500
            
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
        
        # 實現移除黑名單邏輯
        try:
            conn = db_manager.get_connection()
            cursor = conn.cursor()
            
            if db_manager.use_postgresql:
                cursor.execute('''
                    UPDATE blacklist 
                    SET is_active = FALSE, updated_at = %s 
                    WHERE machine_id = %s
                ''', (datetime.now(), machine_id))
            else:
                cursor.execute('''
                    UPDATE blacklist 
                    SET is_active = 0, updated_at = ? 
                    WHERE machine_id = ?
                ''', (db_manager._format_datetime(datetime.now()), machine_id))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            if success:
                logger.info(f"✅ 黑名單移除成功: {machine_id}")
            
            return jsonify({
                'success': success,
                'message': '黑名單移除成功' if success else '黑名單移除失敗'
            })
            
        except Exception as remove_error:
            logger.error(f"❌ 移除黑名單失敗: {remove_error}")
            return jsonify({'success': False, 'error': f'移除失敗: {str(remove_error)}'}), 500
            
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
                SELECT reason, created_date, severity_level 
                FROM blacklist 
                WHERE machine_id = %s AND is_active = TRUE
            ''', (machine_id,))
        else:
            cursor.execute('''
                SELECT reason, created_date, severity_level 
                FROM blacklist 
                WHERE machine_id = ? AND is_active = 1
            ''', (machine_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            reason, created_date, severity_level = result
            return jsonify({
                'blacklisted': True,
                'info': {
                    'reason': reason,
                    'created_date': db_manager._format_datetime(created_date),
                    'severity_level': severity_level if len(result) > 2 else 1
                }
            })
        else:
            return jsonify({'blacklisted': False})
            
    except Exception as e:
        logger.error(f"❌ 檢查黑名單API錯誤: {e}")
        return jsonify({'blacklisted': False, 'error': str(e)}), 500

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
                       force_online, validation_required, expiry_date, check_count
                FROM serials WHERE serial_hash = %s
            ''', (serial_hash,))
        else:
            cursor.execute('''
                SELECT machine_id, user_name, tier, is_active, revoked_date, revoked_reason,
                       force_online, validation_required, expiry_date, check_count
                FROM serials WHERE serial_hash = ?
            ''', (serial_hash,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            (machine_id, user_name, tier, is_active, revoked_date, revoked_reason,
             force_online, validation_required, expiry_date, check_count) = result
            
            return jsonify({
                'found': True,
                'is_active': bool(is_active),
                'info': {
                    'machine_id': machine_id,
                    'user_name': user_name,
                    'tier': tier,
                    'revoked_date': db_manager._format_datetime(revoked_date) if revoked_date else None,
                    'revoked_reason': revoked_reason,
                    'force_online': bool(force_online),
                    'validation_required': bool(validation_required),
                    'expiry_date': db_manager._format_datetime(expiry_date),
                    'check_count': check_count or 0
                }
            })
        else:
            return jsonify({'found': False})
            
    except Exception as e:
        logger.error(f"❌ 檢查序號狀態API錯誤: {e}")
        return jsonify({'found': False, 'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """獲取增強版統計資訊"""
    try:
        stats = db_manager.get_enhanced_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"❌ 統計API錯誤: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# 錯誤處理和工具函數
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': '端點不存在'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"❌ 伺服器內部錯誤: {error}")
    return jsonify({'error': '伺服器內部錯誤'}), 500

@app.before_request
def log_request():
    """記錄API請求"""
    try:
        if request.endpoint and not request.endpoint.startswith('static'):
            # 記錄API使用統計（如果PostgreSQL可用）
            if db_manager.use_postgresql:
                try:
                    conn = db_manager.get_connection()
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        INSERT INTO api_usage_stats 
                        (endpoint, method, client_ip, user_agent, request_time, request_size)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    ''', (
                        request.endpoint,
                        request.method,
                        request.remote_addr,
                        request.headers.get('User-Agent', ''),
                        datetime.now(),
                        len(request.get_data())
                    ))
                    
                    conn.commit()
                    conn.close()
                except Exception as e:
                    pass  # 不影響主要功能
                    
    except Exception as e:
        pass  # 不影響主要功能

# ============================================================================
# 主程式入口點
# ============================================================================

if __name__ == '__main__':
    print("🚀 啟動 BOSS檢測器 Railway 增強版驗證伺服器 v6.0.0...")
    print("="*60)
    print(f"📍 資料庫類型: {'PostgreSQL' if db_manager.use_postgresql else 'SQLite'}")
    print(f"🔍 DATABASE_URL 存在: {bool(db_manager.database_url)}")
    print(f"🔍 psycopg2 可用: {PSYCOPG2_AVAILABLE}")
    print(f"🔒 強制在線驗證: 已啟用")
    print(f"🎯 API版本: 6.0.0")
    print(f"🔑 活躍Token: {len(db_manager.active_tokens)}")
    print("📡 可用的 API 端點:")
    print("  ── 🆕 強制在線驗證端點 ──")
    print("  POST /api/auth/token - 獲取認證Token")
    print("  POST /api/register/enhanced - 增強版序號註冊")
    print("  POST /api/register/force - 強制在線註冊（別名）")
    print("  POST /api/validate/enhanced - 增強版序號驗證")
    print("  POST /api/validate/force - 強制在線驗證（別名）")
    print("  ── 📡 標準API端點 ──")
    print("  GET  / - 增強版首頁")
    print("  GET  /api/health - 健康檢查")
    print("  POST /api/validate - 標準序號驗證")
    print("  POST /api/register - 標準序號註冊")
    print("  POST /api/add - 序號註冊（別名）")
    print("  POST /api/revoke - 停用序號")
    print("  POST /api/restore - 恢復序號")
    print("  POST /api/blacklist - 添加黑名單")
    print("  POST /api/blacklist/remove - 移除黑名單")
    print("  POST /api/blacklist/check - 檢查黑名單")
    print("  POST /api/serial/status - 檢查序號狀態")
    print("  GET  /api/stats - 獲取統計資訊")
    print("="*60)
    print("🔒 強制在線驗證特性:")
    print("  • Token認證機制")
    print("  • 離線保護")
    print("  • 實時服務器驗證")
    print("  • 商業級安全防護")
    print("="*60)
    
    # 開發/生產模式
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)': '管理員認證失敗'}), 403
