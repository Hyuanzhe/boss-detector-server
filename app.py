#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================
  BOSS檢測器 Railway Flask 應用 (PostgreSQL版)
===========================================
作者: @yyv3vnn (Telegram)
功能: Railway 部署的 Flask API 伺服器 (支援 PostgreSQL)
版本: 5.1.1 (修復版)
更新: 2025-08-21
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
        self.admin_key = "boss_admin_2025_integrated_key"
        self.database_url = os.environ.get('DATABASE_URL')
        
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
            
            # 序號表
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
            
            # 黑名單表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blacklist (
                    id SERIAL PRIMARY KEY,
                    machine_id TEXT UNIQUE NOT NULL,
                    reason TEXT,
                    created_date TIMESTAMP NOT NULL,
                    created_by TEXT DEFAULT 'admin'
                )
            ''')
            
            # 驗證日誌表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS validation_logs (
                    id SERIAL PRIMARY KEY,
                    serial_hash TEXT NOT NULL,
                    machine_id TEXT NOT NULL,
                    validation_time TIMESTAMP NOT NULL,
                    result TEXT NOT NULL,
                    client_ip TEXT,
                    user_agent TEXT
                )
            ''')
            
            # 創建索引
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_serial_hash ON serials(serial_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_machine_id ON serials(machine_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_serial_key ON serials(serial_key)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_validation_time ON validation_logs(validation_time)')
            
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
            
            # 序號表
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
                    encryption_type TEXT DEFAULT 'AES+XOR'
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
                    user_agent TEXT
                )
            ''')
            
            # 創建索引
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_serial_hash ON serials(serial_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_machine_id ON serials(machine_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_serial_key ON serials(serial_key)')
            
            conn.commit()
            conn.close()
            print("✅ SQLite 資料庫創建完成")
            logger.info("✅ SQLite 資料庫初始化成功")
            
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
        """解析日期時間字符串"""
        if isinstance(dt_str, datetime):
            return dt_str
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    
    def register_serial(self, serial_key: str, machine_id: str, tier: str, 
                       days: int, user_name: str = "使用者", 
                       encryption_type: str = "AES+XOR") -> bool:
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
                     created_date, expiry_date, created_by, encryption_type)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (serial_key) DO UPDATE SET
                    machine_id = EXCLUDED.machine_id,
                    user_name = EXCLUDED.user_name,
                    tier = EXCLUDED.tier,
                    expiry_date = EXCLUDED.expiry_date,
                    encryption_type = EXCLUDED.encryption_type
                ''', (serial_key, serial_hash, machine_id, user_name, tier, 
                      created_date, expiry_date, 'api', encryption_type))
            else:
                cursor.execute('''
                    INSERT OR REPLACE INTO serials 
                    (serial_key, serial_hash, machine_id, user_name, tier, 
                     created_date, expiry_date, created_by, encryption_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (serial_key, serial_hash, machine_id, user_name, tier, 
                      self._format_datetime(created_date), self._format_datetime(expiry_date), 
                      'api', encryption_type))
            
            conn.commit()
            conn.close()
            logger.info(f"✅ 序號註冊成功: {serial_hash[:8]}...")
            return True
            
        except Exception as e:
            logger.error(f"❌ 註冊序號失敗: {e}")
            return False
    
    def validate_serial(self, serial_key: str, machine_id: str, 
                       client_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """驗證序號"""
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
                                   'BLACKLISTED', client_ip)
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
                    SELECT machine_id, expiry_date, is_active, tier, user_name, check_count
                    FROM serials WHERE serial_hash = %s
                ''', (serial_hash,))
            else:
                cursor.execute('''
                    SELECT machine_id, expiry_date, is_active, tier, user_name, check_count
                    FROM serials WHERE serial_hash = ?
                ''', (serial_hash,))
            
            result = cursor.fetchone()
            
            if not result:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'NOT_FOUND', client_ip)
                conn.commit()
                conn.close()
                return {'valid': False, 'error': '序號不存在'}
            
            stored_machine_id, expiry_date, is_active, tier, user_name, check_count = result
            
            # 檢查機器ID綁定
            if stored_machine_id != machine_id:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'MACHINE_MISMATCH', client_ip)
                conn.commit()
                conn.close()
                return {'valid': False, 'error': '序號已綁定到其他機器'}
            
            # 檢查是否被停用
            if not is_active:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'REVOKED', client_ip)
                conn.commit()
                conn.close()
                return {'valid': False, 'error': '序號已被停用'}
            
            # 檢查過期時間
            expiry_dt = self._parse_datetime(expiry_date)
            if current_time > expiry_dt:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'EXPIRED', client_ip)
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
                               'VALID', client_ip)
            
            conn.commit()
            conn.close()
            
            remaining_days = (expiry_dt - current_time).days
            
            return {
                'valid': True,
                'tier': tier,
                'user_name': user_name,
                'expiry_date': self._format_datetime(expiry_dt),
                'remaining_days': remaining_days,
                'check_count': (check_count or 0) + 1
            }
            
        except Exception as e:
            logger.error(f"❌ 驗證過程錯誤: {e}")
            return {'valid': False, 'error': f'驗證過程錯誤: {str(e)}'}
    
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
            else:
                cursor.execute('SELECT COUNT(*) FROM serials WHERE is_active = 1')
            active_serials = cursor.fetchone()[0]
            
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
            
            conn.close()
            
            return {
                'total_serials': total_serials,
                'active_serials': active_serials,
                'revoked_serials': total_serials - active_serials,
                'blacklist_count': blacklist_count,
                'today_validations': today_validations,
                'database_type': 'PostgreSQL' if self.use_postgresql else 'SQLite',
                'database_url_found': bool(self.database_url),
                'psycopg2_available': PSYCOPG2_AVAILABLE
            }
            
        except Exception as e:
            logger.error(f"❌ 獲取統計失敗: {e}")
            return {
                'database_type': 'PostgreSQL' if self.use_postgresql else 'SQLite',
                'database_url_found': bool(self.database_url),
                'psycopg2_available': PSYCOPG2_AVAILABLE
            }
    
    def _log_validation(self, cursor, serial_hash: str, machine_id: str, 
                       validation_time: datetime, result: str, client_ip: str):
        """記錄驗證日誌"""
        try:
            if self.use_postgresql:
                cursor.execute('''
                    INSERT INTO validation_logs 
                    (serial_hash, machine_id, validation_time, result, client_ip)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (serial_hash, machine_id, validation_time, result, client_ip))
            else:
                cursor.execute('''
                    INSERT INTO validation_logs 
                    (serial_hash, machine_id, validation_time, result, client_ip)
                    VALUES (?, ?, ?, ?, ?)
                ''', (serial_hash, machine_id, self._format_datetime(validation_time), result, client_ip))
        except Exception as e:
            logger.error(f"❌ 記錄驗證日誌失敗: {e}")

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
        <title>BOSS檢測器 Railway 驗證伺服器</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            .status { padding: 15px; margin: 10px 0; border-radius: 5px; }
            .success { background: #d4edda; color: #155724; }
            .info { background: #d1ecf1; color: #0c5460; }
            .warning { background: #fff3cd; color: #856404; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f2f2f2; }
            .db-type { font-weight: bold; color: #007bff; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ BOSS檢測器 Railway 驗證伺服器</h1>
            <div class="status success">
                ✅ 伺服器運行正常 - {{ current_time }}
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
            
            <h2>📊 伺服器狀態</h2>
            <table>
                <tr><th>項目</th><th>狀態</th></tr>
                <tr><td>部署平台</td><td>Railway.app</td></tr>
                <tr><td>資料庫類型</td><td class="db-type">{{ stats.database_type }}</td></tr>
                <tr><td>DATABASE_URL 存在</td><td>{{ '✅ 是' if stats.database_url_found else '❌ 否' }}</td></tr>
                <tr><td>psycopg2 可用</td><td>{{ '✅ 是' if stats.psycopg2_available else '❌ 否' }}</td></tr>
                <tr><td>總序號數</td><td>{{ stats.total_serials }}</td></tr>
                <tr><td>活躍序號</td><td>{{ stats.active_serials }}</td></tr>
                <tr><td>停用序號</td><td>{{ stats.revoked_serials }}</td></tr>
                <tr><td>黑名單數</td><td>{{ stats.blacklist_count }}</td></tr>
                <tr><td>今日驗證</td><td>{{ stats.today_validations }}</td></tr>
            </table>
            
            <h2>🔗 API端點</h2>
            <p>
                <strong>驗證序號:</strong> POST /api/validate<br>
                <strong>註冊序號:</strong> POST /api/register<br>
                <strong>停用序號:</strong> POST /api/revoke<br>
                <strong>恢復序號:</strong> POST /api/restore<br>
                <strong>添加黑名單:</strong> POST /api/blacklist<br>
                <strong>移除黑名單:</strong> POST /api/blacklist/remove<br>
                <strong>獲取統計:</strong> GET /api/stats<br>
                <strong>健康檢查:</strong> GET /api/health
            </p>
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
        'server': 'BOSS檢測器 Railway 驗證伺服器',
        'version': '5.1.1',
        'timestamp': datetime.now().isoformat(),
        'database': stats.get('database_type', 'Unknown'),
        'debug_info': {
            'database_url_found': stats.get('database_url_found', False),
            'psycopg2_available': stats.get('psycopg2_available', False)
        },
        'stats': stats
    })

@app.route('/api/validate', methods=['POST'])
def validate_serial():
    """驗證序號"""
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
        logger.error(f"❌ 驗證API錯誤: {e}")
        return jsonify({'valid': False, 'error': f'驗證失敗: {str(e)}'}), 500

@app.route('/api/register', methods=['POST'])
def register_serial():
    """註冊序號"""
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
    print("🚀 啟動 BOSS檢測器 Railway 驗證伺服器...")
    print(f"📍 資料庫類型: {'PostgreSQL' if db_manager.use_postgresql else 'SQLite'}")
    print(f"🔍 DATABASE_URL 存在: {bool(db_manager.database_url)}")
    print(f"🔍 psycopg2 可用: {PSYCOPG2_AVAILABLE}")
    print("📡 可用的 API 端點:")
    print("  GET  / - 首頁")
    print("  GET  /api/health - 健康檢查")
    print("  POST /api/validate - 驗證序號")
    print("  POST /api/register - 註冊序號")
    print("  GET  /api/stats - 獲取統計")
    print("="*50)
    
    # 開發模式
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
