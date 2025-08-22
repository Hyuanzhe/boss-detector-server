#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================
  BOSS檢測器 Railway Flask 應用 (PostgreSQL版)
===========================================
作者: @yyv3vnn (Telegram)
功能: Railway 部署的 Flask API 伺服器 (支援 PostgreSQL + 強制在線驗證)
版本: 5.2.0 (強制在線增強版)
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
import time

# 在導入其他模組前，先檢查和設置環境變量
print(f"🔍 DATABASE_URL 環境變量: {bool(os.environ.get('DATABASE_URL'))}")
database_url = os.environ.get('DATABASE_URL')
if database_url:
    print(f"✅ 找到 DATABASE_URL: {database_url[:50]}...")
else:
    print("❌ 未找到 DATABASE_URL 環境變數")

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
app.config['SECRET_KEY'] = 'boss_detector_2025_secret_key_enhanced'
app.config['JSON_AS_ASCII'] = False

class EnhancedDatabaseManager:
    """增強版資料庫管理器 - 支援 PostgreSQL、SQLite 和強制在線驗證"""
    
    def __init__(self):
        self.admin_key = "boss_admin_2025_enhanced_key_v6"  # 與客戶端保持一致
        self.master_key = "boss_detector_2025_enhanced_aes_master_key_v6"
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
                print("📝 原因: 未找到 DATABASE_URL 環境變數")
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
        """初始化 PostgreSQL 資料庫（包含遷移邏輯）"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            print("🔧 檢查並創建 PostgreSQL 表...")
            
            # 首先檢查現有表結構
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'serials' AND table_schema = 'public'
            """)
            existing_columns = [row[0] for row in cursor.fetchall()]
            print(f"📋 現有欄位: {existing_columns}")
            
            # 創建基本的序號表（如果不存在）
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
                    encryption_type TEXT DEFAULT 'AES+XOR'
                )
            ''')
            print("✅ 基本序號表檢查完成")
            
            # 遷移邏輯：添加新欄位（如果不存在）
            new_columns = [
                ('force_online', 'BOOLEAN DEFAULT FALSE'),
                ('validation_token', 'TEXT'),
                ('token_expires_at', 'TIMESTAMP'),
                ('version', 'TEXT DEFAULT \'6.0.0\'')
            ]
            
            for column_name, column_definition in new_columns:
                if column_name not in existing_columns:
                    try:
                        cursor.execute(f'ALTER TABLE serials ADD COLUMN {column_name} {column_definition}')
                        print(f"✅ 添加欄位: {column_name}")
                    except Exception as e:
                        print(f"⚠️ 添加欄位 {column_name} 失敗（可能已存在）: {e}")
            
            # 創建其他表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blacklist (
                    id SERIAL PRIMARY KEY,
                    machine_id TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    created_date TIMESTAMP NOT NULL,
                    created_by TEXT DEFAULT 'admin'
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS validation_logs (
                    id SERIAL PRIMARY KEY,
                    serial_hash TEXT NOT NULL,
                    machine_id TEXT NOT NULL,
                    validation_time TIMESTAMP NOT NULL,
                    result TEXT NOT NULL,
                    client_ip TEXT,
                    user_agent TEXT,
                    validation_method TEXT DEFAULT 'standard',
                    force_online BOOLEAN DEFAULT FALSE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS validation_tokens (
                    id SERIAL PRIMARY KEY,
                    token TEXT UNIQUE NOT NULL,
                    created_date TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    used_count INTEGER DEFAULT 0,
                    created_by TEXT DEFAULT 'system'
                )
            ''')
            
            # 創建索引（如果不存在）
            indexes = [
                'CREATE INDEX IF NOT EXISTS idx_serial_hash ON serials(serial_hash)',
                'CREATE INDEX IF NOT EXISTS idx_machine_id ON serials(machine_id)',
                'CREATE INDEX IF NOT EXISTS idx_serial_key ON serials(serial_key)',
                'CREATE INDEX IF NOT EXISTS idx_validation_time ON validation_logs(validation_time)',
                'CREATE INDEX IF NOT EXISTS idx_token ON validation_tokens(token)',
                'CREATE INDEX IF NOT EXISTS idx_force_online ON serials(force_online)'
            ]
            
            for index_sql in indexes:
                try:
                    cursor.execute(index_sql)
                except Exception as e:
                    print(f"⚠️ 創建索引失敗（可能已存在）: {e}")
            
            conn.commit()
            conn.close()
            print("✅ PostgreSQL 資料庫遷移完成")
            logger.info("✅ PostgreSQL 資料庫初始化和遷移成功")
            
        except Exception as e:
            print(f"❌ PostgreSQL 初始化失敗: {e}")
            logger.error(f"❌ PostgreSQL 初始化失敗: {e}")
            # 不要 raise，讓系統回退到 SQLite
            self.use_postgresql = False
            self.db_path = "boss_detector_enhanced.db"
            logger.info("🔄 回退到 SQLite 資料庫")
            self.init_sqlite()

    
    def init_sqlite(self):
        """初始化 SQLite 資料庫（回退方案）"""
        try:
            print("🔧 創建增強版 SQLite 資料庫...")
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 序號表（增強版）
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
                    force_online BOOLEAN DEFAULT 0,
                    validation_token TEXT,
                    token_expires_at TEXT,
                    version TEXT DEFAULT '6.0.0'
                )
            ''')
            
            # 黑名單表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    machine_id TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    created_date TEXT NOT NULL,
                    created_by TEXT DEFAULT 'admin'
                )
            ''')
            
            # 驗證日誌表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS validation_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial_hash TEXT NOT NULL,
                    machine_id TEXT NOT NULL,
                    validation_time TEXT NOT NULL,
                    result TEXT NOT NULL,
                    client_ip TEXT,
                    user_agent TEXT,
                    validation_method TEXT DEFAULT 'standard',
                    force_online BOOLEAN DEFAULT 0
                )
            ''')
            
            # 驗證令牌表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS validation_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT UNIQUE NOT NULL,
                    created_date TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    used_count INTEGER DEFAULT 0,
                    created_by TEXT DEFAULT 'system'
                )
            ''')
            
            # 創建索引
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_serial_hash ON serials(serial_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_machine_id ON serials(machine_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_serial_key ON serials(serial_key)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_force_online ON serials(force_online)')
            
            conn.commit()
            conn.close()
            print("✅ 增強版 SQLite 資料庫創建完成")
            logger.info("✅ 增強版 SQLite 資料庫初始化成功")
            
        except Exception as e:
            print(f"❌ SQLite 初始化失敗: {e}")
            logger.error(f"❌ SQLite 初始化失敗: {e}")
            raise
    
    def hash_serial(self, serial_key: str) -> str:
        """生成序號雜湊"""
        return hashlib.sha256(serial_key.encode('utf-8')).hexdigest()
    
    def _format_datetime(self, dt) -> str:
        """格式化日期時間（兼容 PostgreSQL 和 SQLite）"""
        if isinstance(dt, datetime):
            return dt.isoformat()
        return dt
    
    def _parse_datetime(self, dt_str) -> datetime:
        """解析日期時間字串"""
        if isinstance(dt_str, datetime):
            return dt_str
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    
    def create_validation_token(self, hours: int = 24) -> Dict[str, Any]:
        """創建驗證令牌"""
        try:
            token = str(uuid.uuid4())
            created_date = datetime.now()
            expires_at = created_date + timedelta(hours=hours)
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    INSERT INTO validation_tokens (token, created_date, expires_at)
                    VALUES (%s, %s, %s)
                ''', (token, created_date, expires_at))
            else:
                cursor.execute('''
                    INSERT INTO validation_tokens (token, created_date, expires_at)
                    VALUES (?, ?, ?)
                ''', (token, self._format_datetime(created_date), self._format_datetime(expires_at)))
            
            conn.commit()
            conn.close()
            
            return {
                'token': token,
                'expires_at': expires_at.isoformat(),
                'valid_hours': hours
            }
            
        except Exception as e:
            logger.error(f"❌ 創建驗證令牌失敗: {e}")
            return None
    
    def validate_token(self, token: str) -> bool:
        """驗證令牌"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            current_time = datetime.now()
            
            if self.use_postgresql:
                cursor.execute('''
                    SELECT expires_at, is_active FROM validation_tokens 
                    WHERE token = %s
                ''', (token,))
            else:
                cursor.execute('''
                    SELECT expires_at, is_active FROM validation_tokens 
                    WHERE token = ?
                ''', (token,))
            
            result = cursor.fetchone()
            
            if not result:
                conn.close()
                return False
            
            expires_at, is_active = result
            expires_dt = self._parse_datetime(expires_at)
            
            # 檢查令牌是否有效且未過期
            if is_active and current_time < expires_dt:
                # 更新使用次數
                if self.use_postgresql:
                    cursor.execute('''
                        UPDATE validation_tokens SET used_count = used_count + 1
                        WHERE token = %s
                    ''', (token,))
                else:
                    cursor.execute('''
                        UPDATE validation_tokens SET used_count = used_count + 1
                        WHERE token = ?
                    ''', (token,))
                
                conn.commit()
                conn.close()
                return True
            
            conn.close()
            return False
            
        except Exception as e:
            logger.error(f"❌ 驗證令牌失敗: {e}")
            return False
    
    def register_serial(self, serial_key: str, machine_id: str, tier: str, 
                       days: int, user_name: str = "使用者", 
                       encryption_type: str = "AES+XOR") -> bool:
        """註冊序號到資料庫（增強版）"""
        try:
            serial_hash = self.hash_serial(serial_key)
            created_date = datetime.now()
            expiry_date = created_date + timedelta(days=days)
            
            # 檢查是否為強制在線序號
            force_online = serial_key.startswith('FO60-')
            if force_online:
                encryption_type = f"{encryption_type}+ForceOnline"
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            if self.use_postgresql:
                cursor.execute('''
                    INSERT INTO serials 
                    (serial_key, serial_hash, machine_id, user_name, tier, 
                     created_date, expiry_date, created_by, encryption_type, force_online)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (serial_key) DO UPDATE SET
                    machine_id = EXCLUDED.machine_id,
                    user_name = EXCLUDED.user_name,
                    tier = EXCLUDED.tier,
                    expiry_date = EXCLUDED.expiry_date,
                    encryption_type = EXCLUDED.encryption_type,
                    force_online = EXCLUDED.force_online
                ''', (serial_key, serial_hash, machine_id, user_name, tier, 
                      created_date, expiry_date, 'api', encryption_type, force_online))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO serials 
                    (serial_key, serial_hash, machine_id, user_name, tier, 
                     created_date, expiry_date, created_by, encryption_type, force_online)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (serial_key, serial_hash, machine_id, user_name, tier, 
                      self._format_datetime(created_date), self._format_datetime(expiry_date), 
                      'api', encryption_type, 1 if force_online else 0))
            
            conn.commit()
            conn.close()
            
            if force_online:
                logger.info(f"✅ 強制在線序號註冊成功: {serial_hash[:8]}...")
            else:
                logger.info(f"✅ 序號註冊成功: {serial_hash[:8]}...")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ 註冊序號失敗: {e}")
            return False
    
    def validate_serial(self, serial_key: str, machine_id: str, 
                       client_ip: str = "127.0.0.1", 
                       force_online: bool = False,
                       validation_token: str = None) -> Dict[str, Any]:
        """驗證序號（增強版）"""
        try:
            serial_hash = self.hash_serial(serial_key)
            current_time = datetime.now()
            
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # 檢查黑名單
            if self.use_postgresql:
                cursor.execute('SELECT reason FROM blacklist WHERE machine_id = %s', (machine_id,))
            else:
                cursor.execute('SELECT reason FROM blacklist WHERE machine_id = ?', (machine_id,))
            
            blacklist_result = cursor.fetchone()
            if blacklist_result:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'BLACKLISTED', client_ip, 'force_online' if force_online else 'standard', force_online)
                conn.commit()
                conn.close()
                return {
                    'valid': False,
                    'error': f'機器在黑名單中: {blacklist_result[0]}',
                    'blacklisted': True
                }
            
            # 檢查序號
            if self.use_postgresql:
                cursor.execute('''
                    SELECT machine_id, expiry_date, is_active, tier, user_name, check_count, force_online
                    FROM serials WHERE serial_hash = %s
                ''', (serial_hash,))
            else:
                cursor.execute('''
                    SELECT machine_id, expiry_date, is_active, tier, user_name, check_count, force_online
                    FROM serials WHERE serial_hash = ?
                ''', (serial_hash,))
            
            result = cursor.fetchone()
            
            if not result:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'NOT_FOUND', client_ip, 'force_online' if force_online else 'standard', force_online)
                conn.commit()
                conn.close()
                return {'valid': False, 'error': '序號不存在'}
            
            stored_machine_id, expiry_date, is_active, tier, user_name, check_count, is_force_online = result
            
            # 強制在線序號檢查
            if force_online or is_force_online:
                if not validation_token:
                    conn.close()
                    return {
                        'valid': False, 
                        'error': '強制在線驗證需要驗證令牌',
                        'requires_online': True
                    }
                
                if not self.validate_token(validation_token):
                    conn.close()
                    return {
                        'valid': False, 
                        'error': '驗證令牌無效或已過期',
                        'requires_online': True
                    }
            
            # 檢查機器ID綁定
            if stored_machine_id != machine_id:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'MACHINE_MISMATCH', client_ip, 'force_online' if force_online else 'standard', force_online)
                conn.commit()
                conn.close()
                return {'valid': False, 'error': '序號已綁定到其他機器'}
            
            # 檢查是否被停用
            if not is_active:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'REVOKED', client_ip, 'force_online' if force_online else 'standard', force_online)
                conn.commit()
                conn.close()
                return {'valid': False, 'error': '序號已被停用'}
            
            # 檢查過期時間
            expiry_dt = self._parse_datetime(expiry_date)
            if current_time > expiry_dt:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'EXPIRED', client_ip, 'force_online' if force_online else 'standard', force_online)
                conn.commit()
                conn.close()
                return {'valid': False, 'error': '序號已過期', 'expired': True}
            
            # 更新檢查時間和次數
            if self.use_postgresql:
                cursor.execute('''
                    UPDATE serials 
                    SET last_check_time = %s, check_count = check_count + 1 
                    WHERE serial_hash = %s
                ''', (current_time, serial_hash))
            else:
                cursor.execute('''
                    UPDATE serials 
                    SET last_check_time = ?, check_count = check_count + 1 
                    WHERE serial_hash = ?
                ''', (self._format_datetime(current_time), serial_hash))
            
            self._log_validation(cursor, serial_hash, machine_id, current_time, 
                               'VALID', client_ip, 'force_online' if force_online else 'standard', force_online)
            
            conn.commit()
            conn.close()
            
            remaining_days = (expiry_dt - current_time).days
            
            result_data = {
                'valid': True,
                'tier': tier,
                'user_name': user_name,
                'expiry_date': self._format_datetime(expiry_dt),
                'remaining_days': remaining_days,
                'check_count': (check_count or 0) + 1
            }
            
            # 添加強制在線特定資訊
            if force_online or is_force_online:
                result_data.update({
                    'force_online_verified': True,
                    'validation_method': 'force_online',
                    'server_validated': True
                })
            
            return result_data
            
        except Exception as e:
            logger.error(f"❌ 驗證過程錯誤: {e}")
            return {'valid': False, 'error': f'驗證過程錯誤: {str(e)}'}
    
    def _log_validation(self, cursor, serial_hash: str, machine_id: str, 
                       validation_time: datetime, result: str, client_ip: str,
                       validation_method: str = 'standard', force_online: bool = False):
        """記錄驗證日誌（增強版）"""
        try:
            if self.use_postgresql:
                cursor.execute('''
                    INSERT INTO validation_logs 
                    (serial_hash, machine_id, validation_time, result, client_ip, validation_method, force_online)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                ''', (serial_hash, machine_id, validation_time, result, client_ip, validation_method, force_online))
            else:
                cursor.execute('''
                    INSERT INTO validation_logs 
                    (serial_hash, machine_id, validation_time, result, client_ip, validation_method, force_online)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (serial_hash, machine_id, self._format_datetime(validation_time), result, client_ip, validation_method, 1 if force_online else 0))
        except Exception as e:
            logger.error(f"❌ 記錄驗證日誌失敗: {e}")
    
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
                    (machine_id, reason, created_date)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (machine_id) DO UPDATE SET
                    reason = EXCLUDED.reason,
                    created_date = EXCLUDED.created_date
                ''', (machine_id, reason, created_date))
                
                # 同時停用該機器的所有序號
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = FALSE, revoked_date = %s, revoked_reason = %s
                    WHERE machine_id = %s AND is_active = TRUE
                ''', (created_date, f"黑名單自動停用: {reason}", machine_id))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO blacklist 
                    (machine_id, reason, created_date)
                    VALUES (?, ?, ?)
                ''', (machine_id, reason, self._format_datetime(created_date)))
                
                cursor.execute('''
                    UPDATE serials 
                    SET is_active = 0, revoked_date = ?, revoked_reason = ?
                    WHERE machine_id = ? AND is_active = 1
                ''', (self._format_datetime(created_date), f"黑名單自動停用: {reason}", machine_id))
            
            conn.commit()
            conn.close()
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
                cursor.execute('DELETE FROM blacklist WHERE machine_id = %s', (machine_id,))
            else:
                cursor.execute('DELETE FROM blacklist WHERE machine_id = ?', (machine_id,))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            if success:
                logger.info(f"✅ 黑名單移除成功: {machine_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"❌ 移除黑名單失敗: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """獲取統計資訊（增強版）"""
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # 總序號數
            cursor.execute('SELECT COUNT(*) FROM serials')
            total_serials = cursor.fetchone()[0]
            
            # 活躍序號數
            if self.use_postgresql:
                cursor.execute('SELECT COUNT(*) FROM serials WHERE is_active = TRUE')
            else:
                cursor.execute('SELECT COUNT(*) FROM serials WHERE is_active = 1')
            active_serials = cursor.fetchone()[0]
            
            # 強制在線序號數
            if self.use_postgresql:
                cursor.execute('SELECT COUNT(*) FROM serials WHERE force_online = TRUE')
            else:
                cursor.execute('SELECT COUNT(*) FROM serials WHERE force_online = 1')
            force_online_serials = cursor.fetchone()[0]
            
            # 黑名單數
            cursor.execute('SELECT COUNT(*) FROM blacklist')
            blacklist_count = cursor.fetchone()[0]
            
            # 今日驗證數
            if self.use_postgresql:
                cursor.execute("SELECT COUNT(*) FROM validation_logs WHERE DATE(validation_time) = CURRENT_DATE")
            else:
                today = datetime.now().date().isoformat()
                cursor.execute('SELECT COUNT(*) FROM validation_logs WHERE DATE(validation_time) = ?', (today,))
            today_validations = cursor.fetchone()[0]
            
            # 強制在線驗證數
            if self.use_postgresql:
                cursor.execute("SELECT COUNT(*) FROM validation_logs WHERE force_online = TRUE AND DATE(validation_time) = CURRENT_DATE")
            else:
                cursor.execute('SELECT COUNT(*) FROM validation_logs WHERE force_online = 1 AND DATE(validation_time) = ?', (today,))
            today_force_online_validations = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_serials': total_serials,
                'active_serials': active_serials,
                'revoked_serials': total_serials - active_serials,
                'force_online_serials': force_online_serials,
                'blacklist_count': blacklist_count,
                'today_validations': today_validations,
                'today_force_online_validations': today_force_online_validations,
                'database_type': 'PostgreSQL' if self.use_postgresql else 'SQLite',
                'database_url_found': bool(self.database_url),
                'psycopg2_available': PSYCOPG2_AVAILABLE,
                'force_online_support': True,
                'enhanced_version': '5.2.0'
            }
            
        except Exception as e:
            logger.error(f"❌ 獲取統計失敗: {e}")
            return {
                'database_type': 'PostgreSQL' if self.use_postgresql else 'SQLite',
                'database_url_found': bool(self.database_url),
                'psycopg2_available': PSYCOPG2_AVAILABLE,
                'force_online_support': True,
                'enhanced_version': '5.2.0',
                'error': str(e)
            }

# 初始化增強版資料庫管理器
try:
    print("🚀 初始化增強版資料庫管理器...")
    db_manager = EnhancedDatabaseManager()
    print("✅ 增強版資料庫管理器初始化完成")
    logger.info("✅ 增強版資料庫管理器初始化成功")
except Exception as e:
    print(f"❌ 增強版資料庫管理器初始化失敗: {e}")
    logger.error(f"❌ 增強版資料庫管理器初始化失敗: {e}")
    sys.exit(1)

# API 路由（增強版）
@app.route('/')
def home():
    """首頁（增強版）"""
    stats = db_manager.get_statistics()
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BOSS檢測器 Railway 驗證伺服器（增強版）</title>
        <meta charset="utf-8">
        <style>
            body { font-family: 'Microsoft JhengHei', Arial; margin: 40px; background: #f5f5f5; }
            .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .status { padding: 15px; margin: 10px 0; border-radius: 5px; }
            .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
            .warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
            .enhanced { background: #e7f3ff; color: #004085; border: 1px solid #b3d7ff; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f8f9fa; font-weight: bold; }
            .db-type { font-weight: bold; color: #007bff; }
            .force-online { color: #dc3545; font-weight: bold; }
            .badge { padding: 3px 8px; border-radius: 3px; font-size: 0.85em; font-weight: bold; }
            .badge-success { background: #28a745; color: white; }
            .badge-info { background: #17a2b8; color: white; }
            .badge-warning { background: #ffc107; color: #212529; }
            h1 { color: #2c3e50; margin-bottom: 20px; }
            h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
            .endpoint-list { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }
            .endpoint-list strong { color: #2c3e50; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ BOSS檢測器 Railway 驗證伺服器（增強版）</h1>
            <div class="status success">
                ✅ 伺服器運行正常 - {{ current_time }}
                <span class="badge badge-info">v{{ stats.enhanced_version }}</span>
            </div>
            
            {% if stats.force_online_support %}
            <div class="status enhanced">
                🔒 <span class="force-online">強制在線驗證支援</span> - 已啟用防離線破解保護
            </div>
            {% endif %}
            
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
            
            <h2>📊 伺服器狀態</h2>
            <table>
                <tr><th>項目</th><th>狀態</th></tr>
                <tr><td>部署平台</td><td><span class="badge badge-info">Railway.app</span></td></tr>
                <tr><td>資料庫類型</td><td class="db-type">{{ stats.database_type }}</td></tr>
                <tr><td>DATABASE_URL 存在</td><td>{{ '✅ 是' if stats.database_url_found else '❌ 否' }}</td></tr>
                <tr><td>psycopg2 可用</td><td>{{ '✅ 是' if stats.psycopg2_available else '❌ 否' }}</td></tr>
                <tr><td>強制在線支援</td><td><span class="force-online">{{ '✅ 已啟用' if stats.force_online_support else '❌ 未啟用' }}</span></td></tr>
                <tr><td>總序號數</td><td>{{ stats.total_serials }}</td></tr>
                <tr><td>活躍序號</td><td><span class="badge badge-success">{{ stats.active_serials }}</span></td></tr>
                <tr><td>停用序號</td><td><span class="badge badge-warning">{{ stats.revoked_serials }}</span></td></tr>
                <tr><td>強制在線序號</td><td><span class="force-online">{{ stats.force_online_serials }}</span></td></tr>
                <tr><td>黑名單數</td><td>{{ stats.blacklist_count }}</td></tr>
                <tr><td>今日驗證</td><td>{{ stats.today_validations }}</td></tr>
                <tr><td>今日強制在線驗證</td><td><span class="force-online">{{ stats.today_force_online_validations }}</span></td></tr>
            </table>
            
            <h2>🔗 API端點（增強版）</h2>
            
            <div class="endpoint-list">
                <h3>🔒 強制在線驗證端點</h3>
                <strong>獲取驗證令牌:</strong> POST /api/auth/token<br>
                <strong>增強版註冊:</strong> POST /api/register/enhanced<br>
                <strong>強制註冊:</strong> POST /api/register/force<br>
                <strong>增強版驗證:</strong> POST /api/validate/enhanced<br>
                <strong>強制驗證:</strong> POST /api/validate/force<br>
            </div>
            
            <div class="endpoint-list">
                <h3>📝 標準端點</h3>
                <strong>驗證序號:</strong> POST /api/validate<br>
                <strong>註冊序號:</strong> POST /api/register<br>
                <strong>添加序號:</strong> POST /api/add<br>
            </div>
            
            <div class="endpoint-list">
                <h3>🛠️ 管理端點</h3>
                <strong>停用序號:</strong> POST /api/revoke<br>
                <strong>恢復序號:</strong> POST /api/restore<br>
                <strong>添加黑名單:</strong> POST /api/blacklist<br>
                <strong>移除黑名單:</strong> POST /api/blacklist/remove<br>
                <strong>檢查黑名單:</strong> POST /api/blacklist/check<br>
                <strong>序號狀態:</strong> POST /api/serial/status<br>
            </div>
            
            <div class="endpoint-list">
                <h3>📊 狀態端點</h3>
                <strong>獲取統計:</strong> GET /api/stats<br>
                <strong>健康檢查:</strong> GET /api/health<br>
                <strong>API狀態:</strong> GET /api/status<br>
            </div>
        </div>
    </body>
    </html>
    ''', current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), stats=stats)

@app.route('/api/health')
def health_check():
    """健康檢查（增強版）"""
    stats = db_manager.get_statistics()
    return jsonify({
        'status': 'healthy',
        'server': 'BOSS檢測器 Railway 驗證伺服器（增強版）',
        'version': '5.2.0',
        'timestamp': datetime.now().isoformat(),
        'database': stats.get('database_type', 'Unknown'),
        'force_online_support': True,
        'enhanced_features': [
            'force_online_validation',
            'validation_tokens',
            'enhanced_logging',
            'postgresql_support'
        ],
        'debug_info': {
            'database_url_found': stats.get('database_url_found', False),
            'psycopg2_available': stats.get('psycopg2_available', False)
        },
        'stats': stats
    })

@app.route('/api/status')
def api_status():
    """API狀態檢查（增強版）"""
    try:
        stats = db_manager.get_statistics()
        
        return jsonify({
            'status': 'healthy',
            'server': 'BOSS檢測器 Railway 驗證伺服器（增強版）',
            'version': '5.2.0',
            'timestamp': datetime.now().isoformat(),
            'database': stats.get('database_type', 'Unknown'),
            'force_online_support': True,
            'enhanced_validation': True,
            'available_endpoints': [
                '/api/health',
                '/api/status',
                '/api/validate',
                '/api/validate/enhanced', 
                '/api/validate/force',
                '/api/register',
                '/api/register/enhanced',
                '/api/register/force',
                '/api/add',
                '/api/auth/token',
                '/api/revoke',
                '/api/restore',
                '/api/blacklist',
                '/api/blacklist/remove',
                '/api/blacklist/check',
                '/api/serial/status',
                '/api/stats'
            ],
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"❌ 狀態檢查錯誤: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500

# 強制在線驗證相關端點
@app.route('/api/auth/token', methods=['POST'])
def get_validation_token():
    """獲取驗證令牌（強制在線驗證用）"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '無效的請求資料'}), 400
        
        admin_key = data.get('admin_key')
        request_type = data.get('request_type')
        
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        if request_type != 'validation':
            return jsonify({'success': False, 'error': '無效的請求類型'}), 400
        
        # 創建驗證令牌
        token_info = db_manager.create_validation_token(hours=24)
        
        if token_info:
            return jsonify({
                'success': True,
                'token': token_info['token'],
                'expires_at': token_info['expires_at'],
                'valid_hours': token_info['valid_hours']
            })
        else:
            return jsonify({'success': False, 'error': '無法創建驗證令牌'}), 500
        
    except Exception as e:
        logger.error(f"❌ 獲取驗證令牌錯誤: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/register/enhanced', methods=['POST'])
def register_enhanced():
    """增強版註冊端點（支持強制在線驗證）"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': '無效的請求資料'}), 400
        
        # 檢查管理員認證
        admin_key = data.get('admin_key')
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        # 檢查驗證令牌（強制在線驗證）
        validation_token = data.get('validation_token')
        if not validation_token:
            return jsonify({'success': False, 'error': '缺少驗證令牌'}), 400
        
        if not db_manager.validate_token(validation_token):
            return jsonify({'success': False, 'error': '驗證令牌無效或已過期'}), 400
        
        # 獲取註冊參數
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        tier = data.get('tier', 'trial')
        days = data.get('days', 7)
        user_name = data.get('user_name', '使用者')
        encryption_type = data.get('encryption_type', 'AES+XOR+ForceOnline')
        force_online = data.get('force_online', True)
        version = data.get('version', '6.0.0')
        
        if not serial_key or not machine_id:
            return jsonify({'success': False, 'error': '缺少必要參數'}), 400
        
        # 驗證序號格式（強制在線序號應該有特殊前綴）
        if force_online and not serial_key.startswith('FO60-'):
            return jsonify({'success': False, 'error': '無效的強制在線序號格式'}), 400
        
        # 檢查校驗和（如果提供）
        checksum = data.get('checksum')
        if checksum:
            expected_checksum = hashlib.sha256(f"{serial_key}{machine_id}{admin_key}".encode()).hexdigest()
            if checksum != expected_checksum:
                return jsonify({'success': False, 'error': '校驗和驗證失敗'}), 400
        
        # 註冊序號
        success = db_manager.register_serial(
            serial_key, machine_id, tier, days, user_name, encryption_type
        )
        
        if success:
            # 記錄強制在線註冊
            logger.info(f"✅ 強制在線序號註冊成功: {serial_key[:20]}... (機器ID: {machine_id})")
            
            # 生成新的令牌（可選）
            new_token_info = db_manager.create_validation_token(hours=24)
            
            response_data = {
                'success': True,
                'registered': True,
                'force_registered': True,
                'message': '強制在線序號註冊成功',
                'serial_info': {
                    'serial_key': serial_key[:30] + '...',
                    'machine_id': machine_id,
                    'tier': tier,
                    'days': days,
                    'force_online': force_online,
                    'encryption_type': encryption_type
                }
            }
            
            if new_token_info:
                response_data['new_token'] = new_token_info['token']
                response_data['token_expires'] = new_token_info['expires_at']
            
            return jsonify(response_data)
        else:
            return jsonify({
                'success': False, 
                'error': '強制在線序號註冊失敗'
            }), 500
        
    except Exception as e:
        logger.error(f"❌ 增強註冊API錯誤: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/register/force', methods=['POST'])
def register_force():
    """強制註冊端點"""
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
        encryption_type = data.get('encryption_type', 'ForceOnline')
        
        if not serial_key or not machine_id:
            return jsonify({'success': False, 'error': '缺少必要參數'}), 400
        
        # 強制註冊（覆蓋現有記錄）
        success = db_manager.register_serial(serial_key, machine_id, tier, days, user_name, encryption_type)
        
        return jsonify({
            'success': success,
            'force_registered': success,
            'message': '強制註冊完成' if success else '強制註冊失敗'
        })
        
    except Exception as e:
        logger.error(f"❌ 強制註冊API錯誤: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/add', methods=['POST'])
def add_serial():
    """添加序號端點（兼容性端點）"""
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
        encryption_type = data.get('encryption_type', 'Standard')
        
        if not serial_key or not machine_id:
            return jsonify({'success': False, 'error': '缺少必要參數'}), 400
        
        success = db_manager.register_serial(serial_key, machine_id, tier, days, user_name, encryption_type)
        
        return jsonify({
            'success': success,
            'added': success,
            'message': '序號添加成功' if success else '序號添加失敗'
        })
        
    except Exception as e:
        logger.error(f"❌ 添加序號API錯誤: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/validate/enhanced', methods=['POST'])
def validate_enhanced():
    """增強版驗證端點（支持強制在線驗證）"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'error': '無效的請求資料'}), 400
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        validation_token = data.get('validation_token')
        force_online = data.get('force_online', False)
        client_ip = data.get('client_ip', request.remote_addr)
        
        if not serial_key or not machine_id:
            return jsonify({'valid': False, 'error': '缺少必要參數'}), 400
        
        # 強制在線驗證需要驗證令牌
        if force_online and not validation_token:
            return jsonify({
                'valid': False, 
                'error': '強制在線驗證需要驗證令牌',
                'requires_online': True
            }), 400
        
        # 檢查校驗和（如果提供）
        checksum = data.get('checksum')
        if checksum:
            expected_checksum = hashlib.sha256(f"{serial_key}{machine_id}".encode()).hexdigest()
            if checksum != expected_checksum:
                return jsonify({'valid': False, 'error': '校驗和驗證失敗'}), 400
        
        # 執行序號驗證
        result = db_manager.validate_serial(serial_key, machine_id, client_ip, force_online, validation_token)
        
        # 為強制在線驗證添加額外檢查
        if force_online and result.get('valid', False):
            # 檢查序號是否為強制在線類型
            if not serial_key.startswith('FO60-'):
                result['valid'] = False
                result['error'] = '非強制在線序號'
                result['requires_online'] = True
            else:
                # 添加強制在線特定資訊
                result['force_online_verified'] = True
                result['validation_method'] = 'force_online'
                result['server_validated'] = True
        
        # 生成新令牌（如果驗證成功且是強制在線）
        if result.get('valid', False) and force_online:
            new_token_info = db_manager.create_validation_token(hours=24)
            if new_token_info:
                result['new_token'] = new_token_info['token']
                result['token_expires'] = new_token_info['expires_at']
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"❌ 增強驗證API錯誤: {e}")
        return jsonify({'valid': False, 'error': str(e)}), 500

@app.route('/api/validate/force', methods=['POST'])
def validate_force():
    """強制驗證端點"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'error': '無效的請求資料'}), 400
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        client_ip = data.get('client_ip', request.remote_addr)
        
        if not serial_key or not machine_id:
            return jsonify({'valid': False, 'error': '缺少必要參數'}), 400
        
        # 執行強制驗證（忽略某些限制）
        result = db_manager.validate_serial(serial_key, machine_id, client_ip)
        
        # 添加強制驗證標記
        if result.get('valid', False):
            result['force_validated'] = True
            result['validation_method'] = 'force'
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"❌ 強制驗證API錯誤: {e}")
        return jsonify({'valid': False, 'error': str(e)}), 500

# 標準端點
@app.route('/api/validate', methods=['POST'])
def validate_serial():
    """驗證序號（標準端點）"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'error': '無效的請求資料'}), 400
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        
        if not serial_key or not machine_id:
            return jsonify({'valid': False, 'error': '缺少必要參數'}), 400
        
        client_ip = request.remote_addr
        
        # 檢查是否為強制在線序號
        force_online = serial_key.startswith('FO60-')
        validation_token = data.get('validation_token') if force_online else None
        
        result = db_manager.validate_serial(serial_key, machine_id, client_ip, force_online, validation_token)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"❌ 驗證API錯誤: {e}")
        return jsonify({'valid': False, 'error': f'驗證失敗: {str(e)}'}), 500

@app.route('/api/register', methods=['POST'])
def register_serial():
    """註冊序號（標準端點）"""
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
            'message': '序號註冊成功' if success else '序號註冊失敗'
        })
        
    except Exception as e:
        logger.error(f"❌ 註冊API錯誤: {e}")
        return jsonify({'success': False, 'error': f'註冊失敗: {str(e)}'}), 500

# 管理端點
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
            cursor.execute('SELECT reason, created_date FROM blacklist WHERE machine_id = %s', (machine_id,))
        else:
            cursor.execute('SELECT reason, created_date FROM blacklist WHERE machine_id = ?', (machine_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return jsonify({
                'blacklisted': True,
                'info': {
                    'reason': result[0],
                    'created_date': db_manager._format_datetime(result[1])
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
                SELECT machine_id, user_name, tier, is_active, revoked_date, revoked_reason, force_online
                FROM serials WHERE serial_hash = %s
            ''', (serial_hash,))
        else:
            cursor.execute('''
                SELECT machine_id, user_name, tier, is_active, revoked_date, revoked_reason, force_online
                FROM serials WHERE serial_hash = ?
            ''', (serial_hash,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            machine_id, user_name, tier, is_active, revoked_date, revoked_reason, force_online = result
            return jsonify({
                'found': True,
                'is_active': bool(is_active),
                'is_force_online': bool(force_online),
                'info': {
                    'machine_id': machine_id,
                    'user_name': user_name,
                    'tier': tier,
                    'revoked_date': db_manager._format_datetime(revoked_date) if revoked_date else None,
                    'revoked_reason': revoked_reason,
                    'force_online': bool(force_online)
                }
            })
        else:
            return jsonify({'found': False})
            
    except Exception as e:
        logger.error(f"❌ 檢查序號狀態API錯誤: {e}")
        return jsonify({'found': False, 'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """獲取統計資訊"""
    try:
        stats = db_manager.get_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"❌ 統計API錯誤: {e}")
        return jsonify({'error': str(e)}), 500

# 錯誤處理
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': '端點不存在'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"❌ 伺服器內部錯誤: {error}")
    return jsonify({'error': '伺服器內部錯誤'}), 500

# 主程式入口點
if __name__ == '__main__':
    print("🚀 啟動 BOSS檢測器 Railway 驗證伺服器（增強版）...")
    print(f"📍 資料庫類型: {'PostgreSQL' if db_manager.use_postgresql else 'SQLite'}")
    print(f"🔍 DATABASE_URL 存在: {bool(db_manager.database_url)}")
    print(f"🔍 psycopg2 可用: {PSYCOPG2_AVAILABLE}")
    print(f"🔒 強制在線驗證支援: ✅ 已啟用")
    print("📡 可用的 API 端點:")
    print("  === 標準端點 ===")
    print("  GET  / - 首頁")
    print("  GET  /api/health - 健康檢查")
    print("  GET  /api/status - API狀態")
    print("  POST /api/validate - 驗證序號")
    print("  POST /api/register - 註冊序號")
    print("  GET  /api/stats - 獲取統計")
    print("")
    print("  === 強制在線端點 ===")
    print("  POST /api/auth/token - 獲取驗證令牌")
    print("  POST /api/register/enhanced - 增強版註冊")
    print("  POST /api/register/force - 強制註冊")
    print("  POST /api/validate/enhanced - 增強版驗證")
    print("  POST /api/validate/force - 強制驗證")
    print("  POST /api/add - 添加序號（兼容性）")
    print("")
    print("  === 管理端點 ===")
    print("  POST /api/revoke - 停用序號")
    print("  POST /api/restore - 恢復序號")
    print("  POST /api/blacklist - 添加黑名單")
    print("  POST /api/blacklist/remove - 移除黑名單")
    print("  POST /api/blacklist/check - 檢查黑名單")
    print("  POST /api/serial/status - 檢查序號狀態")
    print("="*60)
    
    # 開發模式
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

