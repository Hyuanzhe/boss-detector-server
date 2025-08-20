#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================
  BOSS檢測器 Railway Flask 應用
===========================================
作者: @yyv3vnn (Telegram)
功能: Railway 部署的 Flask API 伺服器
版本: 5.0.1 (Railway版)
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
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

os.environ['TZ'] = 'Asia/Taipei'

# 創建 Flask 應用實例
app = Flask(__name__)
CORS(app)

# 配置
app.config['SECRET_KEY'] = 'boss_detector_2025_secret_key'
app.config['JSON_AS_ASCII'] = False

class DatabaseManager:
    """資料庫管理器"""
    
    def __init__(self, db_path: str = "boss_detector.db"):
        self.db_path = db_path
        self.admin_key = "boss_admin_2025_integrated_key"
        self.init_database()
    
    def init_database(self):
        """初始化資料庫"""
        try:
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
            print("✅ 資料庫初始化成功")
            
        except Exception as e:
            print(f"❌ 資料庫初始化失敗: {e}")
    
    def hash_serial(self, serial_key: str) -> str:
        """生成序號雜湊"""
        return hashlib.sha256(serial_key.encode('utf-8')).hexdigest()
    
    def register_serial(self, serial_key: str, machine_id: str, tier: str, 
                       days: int, user_name: str = "使用者", 
                       encryption_type: str = "AES+XOR") -> bool:
        """註冊序號到資料庫"""
        try:
            serial_hash = self.hash_serial(serial_key)
            created_date = datetime.now().isoformat()
            expiry_date = (datetime.now() + timedelta(days=days)).isoformat()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO serials 
                (serial_key, serial_hash, machine_id, user_name, tier, 
                 created_date, expiry_date, created_by, encryption_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (serial_key, serial_hash, machine_id, user_name, tier, 
                  created_date, expiry_date, 'api', encryption_type))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"註冊序號失敗: {e}")
            return False
    
    def validate_serial(self, serial_key: str, machine_id: str, 
                       client_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """驗證序號"""
        try:
            serial_hash = self.hash_serial(serial_key)
            current_time = datetime.now().isoformat()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 檢查黑名單
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
            expiry_dt = datetime.fromisoformat(expiry_date)
            if datetime.now() > expiry_dt:
                self._log_validation(cursor, serial_hash, machine_id, current_time, 
                                   'EXPIRED', client_ip)
                conn.commit()
                conn.close()
                return {'valid': False, 'error': '序號已過期', 'expired': True}
            
            # 更新檢查時間和次數
            cursor.execute('''
                UPDATE serials 
                SET last_check_time = ?, check_count = check_count + 1 
                WHERE serial_hash = ?
            ''', (current_time, serial_hash))
            
            self._log_validation(cursor, serial_hash, machine_id, current_time, 
                               'VALID', client_ip)
            
            conn.commit()
            conn.close()
            
            remaining_days = (expiry_dt - datetime.now()).days
            
            return {
                'valid': True,
                'tier': tier,
                'user_name': user_name,
                'expiry_date': expiry_date,
                'remaining_days': remaining_days,
                'check_count': check_count + 1
            }
            
        except Exception as e:
            return {'valid': False, 'error': f'驗證過程錯誤: {str(e)}'}
    
    def revoke_serial(self, serial_key: str, reason: str = "管理員停用") -> bool:
        """停用序號"""
        try:
            serial_hash = self.hash_serial(serial_key)
            revoked_date = datetime.now().isoformat()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE serials 
                SET is_active = 0, revoked_date = ?, revoked_reason = ?
                WHERE serial_hash = ?
            ''', (revoked_date, reason, serial_hash))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            return success
            
        except Exception as e:
            print(f"停用序號失敗: {e}")
            return False
    
    def restore_serial(self, serial_key: str) -> bool:
        """恢復序號"""
        try:
            serial_hash = self.hash_serial(serial_key)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE serials 
                SET is_active = 1, revoked_date = NULL, revoked_reason = NULL
                WHERE serial_hash = ?
            ''', (serial_hash,))
            
            success = cursor.rowcount > 0
            conn.commit()
            conn.close()
            
            return success
            
        except Exception as e:
            print(f"恢復序號失敗: {e}")
            return False
    
    def add_to_blacklist(self, machine_id: str, reason: str = "違規使用") -> bool:
        """添加到黑名單"""
        try:
            created_date = datetime.now().isoformat()
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO blacklist 
                (machine_id, reason, created_date)
                VALUES (?, ?, ?)
            ''', (machine_id, reason, created_date))
            
            # 同時停用該機器的所有序號
            cursor.execute('''
                UPDATE serials 
                SET is_active = 0, revoked_date = ?, revoked_reason = ?
                WHERE machine_id = ? AND is_active = 1
            ''', (created_date, f"黑名單自動停用: {reason}", machine_id))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"添加黑名單失敗: {e}")
            return False
    
    def remove_from_blacklist(self, machine_id: str) -> bool:
        """從黑名單移除"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM blacklist WHERE machine_id = ?', (machine_id,))
            success = cursor.rowcount > 0
            
            conn.commit()
            conn.close()
            return success
            
        except Exception as e:
            print(f"移除黑名單失敗: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """獲取統計資訊"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 總序號數
            cursor.execute('SELECT COUNT(*) FROM serials')
            total_serials = cursor.fetchone()[0]
            
            # 活躍序號數
            cursor.execute('SELECT COUNT(*) FROM serials WHERE is_active = 1')
            active_serials = cursor.fetchone()[0]
            
            # 黑名單數
            cursor.execute('SELECT COUNT(*) FROM blacklist')
            blacklist_count = cursor.fetchone()[0]
            
            # 今日驗證數
            today = datetime.now().date().isoformat()
            cursor.execute('SELECT COUNT(*) FROM validation_logs WHERE DATE(validation_time) = ?', (today,))
            today_validations = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_serials': total_serials,
                'active_serials': active_serials,
                'revoked_serials': total_serials - active_serials,
                'blacklist_count': blacklist_count,
                'today_validations': today_validations
            }
            
        except Exception as e:
            print(f"獲取統計失敗: {e}")
            return {}
    
    def _log_validation(self, cursor, serial_hash: str, machine_id: str, 
                       validation_time: str, result: str, client_ip: str):
        """記錄驗證日誌"""
        cursor.execute('''
            INSERT INTO validation_logs 
            (serial_hash, machine_id, validation_time, result, client_ip)
            VALUES (?, ?, ?, ?, ?)
        ''', (serial_hash, machine_id, validation_time, result, client_ip))

# 初始化資料庫管理器
db_manager = DatabaseManager()

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
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ BOSS檢測器 Railway 驗證伺服器</h1>
            <div class="status success">
                ✅ 伺服器運行正常 - {{ current_time }}
            </div>
            
            <h2>📊 伺服器狀態</h2>
            <table>
                <tr><th>項目</th><th>狀態</th></tr>
                <tr><td>部署平台</td><td>Railway.app</td></tr>
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
    return jsonify({
        'status': 'healthy',
        'server': 'BOSS檢測器 Railway 驗證伺服器',
        'version': '5.0.1',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected'
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
        return jsonify({'success': False, 'error': f'註冊失敗: {str(e)}'}), 500

@app.route('/api/revoke', methods=['POST'])
def revoke_serial():
    """停用序號"""
    try:
        data = request.get_json()
        admin_key = data.get('admin_key')
        
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        serial_key = data.get('serial_key')
        reason = data.get('reason', '管理員停用')
        
        success = db_manager.revoke_serial(serial_key, reason)
        
        return jsonify({
            'success': success,
            'message': '序號停用成功' if success else '序號停用失敗'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/restore', methods=['POST'])
def restore_serial():
    """恢復序號"""
    try:
        data = request.get_json()
        admin_key = data.get('admin_key')
        
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        serial_key = data.get('serial_key')
        success = db_manager.restore_serial(serial_key)
        
        return jsonify({
            'success': success,
            'message': '序號恢復成功' if success else '序號恢復失敗'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/blacklist', methods=['POST'])
def add_blacklist():
    """添加黑名單"""
    try:
        data = request.get_json()
        admin_key = data.get('admin_key')
        
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        machine_id = data.get('machine_id')
        reason = data.get('reason', '違規使用')
        
        success = db_manager.add_to_blacklist(machine_id, reason)
        
        return jsonify({
            'success': success,
            'message': '黑名單添加成功' if success else '黑名單添加失敗'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/blacklist/remove', methods=['POST'])
def remove_blacklist():
    """移除黑名單"""
    try:
        data = request.get_json()
        admin_key = data.get('admin_key')
        
        if admin_key != db_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        machine_id = data.get('machine_id')
        success = db_manager.remove_from_blacklist(machine_id)
        
        return jsonify({
            'success': success,
            'message': '黑名單移除成功' if success else '黑名單移除失敗'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """獲取統計資訊"""
    try:
        stats = db_manager.get_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blacklist/check', methods=['POST'])
def check_blacklist():
    """檢查黑名單狀態"""
    try:
        data = request.get_json()
        machine_id = data.get('machine_id')
        
        if not machine_id:
            return jsonify({'blacklisted': False, 'error': '缺少機器ID'}), 400
        
        conn = sqlite3.connect(db_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT reason, created_date FROM blacklist WHERE machine_id = ?', (machine_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return jsonify({
                'blacklisted': True,
                'info': {
                    'reason': result[0],
                    'created_date': result[1]
                }
            })
        else:
            return jsonify({'blacklisted': False})
            
    except Exception as e:
        return jsonify({'blacklisted': False, 'error': str(e)}), 500

@app.route('/api/serial/status', methods=['POST'])
def check_serial_status():
    """檢查序號狀態"""
    try:
        data = request.get_json()
        admin_key = data.get('admin_key')
        
        if admin_key != db_manager.admin_key:
            return jsonify({'found': False, 'error': '管理員認證失敗'}), 403
        
        serial_key = data.get('serial_key')
        if not serial_key:
            return jsonify({'found': False, 'error': '缺少序號'}), 400
        
        serial_hash = db_manager.hash_serial(serial_key)
        
        conn = sqlite3.connect(db_manager.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT machine_id, user_name, tier, is_active, revoked_date, revoked_reason
            FROM serials WHERE serial_hash = ?
        ''', (serial_hash,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            machine_id, user_name, tier, is_active, revoked_date, revoked_reason = result
            return jsonify({
                'found': True,
                'is_active': bool(is_active),
                'info': {
                    'machine_id': machine_id,
                    'user_name': user_name,
                    'tier': tier,
                    'revoked_date': revoked_date,
                    'revoked_reason': revoked_reason
                }
            })
        else:
            return jsonify({'found': False})
            
    except Exception as e:
        return jsonify({'found': False, 'error': str(e)}), 500

# 錯誤處理
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': '端點不存在'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': '伺服器內部錯誤'}), 500

# 主程式入口點
if __name__ == '__main__':
    print("🚀 啟動 BOSS檢測器 Railway 驗證伺服器...")
    print("📡 可用的 API 端點:")
    print("  GET  / - 首頁")
    print("  GET  /api/health - 健康檢查")
    print("  POST /api/validate - 驗證序號")
    print("  POST /api/register - 註冊序號")
    print("  POST /api/revoke - 停用序號")
    print("  POST /api/restore - 恢復序號")
    print("  POST /api/blacklist - 添加黑名單")
    print("  POST /api/blacklist/remove - 移除黑名單")
    print("  POST /api/blacklist/check - 檢查黑名單")
    print("  POST /api/serial/status - 檢查序號狀態")
    print("  GET  /api/stats - 獲取統計")
    print("="*50)
    
    # 開發模式
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)



