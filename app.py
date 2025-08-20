#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BOSS檢測器 Railway 部署版本
"""

import os
import sys
import json
import sqlite3
import hashlib
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

class RailwayServerManager:
    """Railway 專用伺服器管理器"""
    
    def __init__(self, db_path: str = "railway_serials.db"):
        self.db_path = db_path
        self.admin_key = "boss_admin_2025_railway_key"  # Railway專用密鑰
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
                    created_by TEXT DEFAULT 'railway',
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
            
            # 建立索引
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_serial_hash ON serials(serial_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_machine_id ON serials(machine_id)')
            
            conn.commit()
            conn.close()
            
            print("✅ Railway資料庫初始化成功")
            
        except Exception as e:
            print(f"❌ 資料庫初始化失敗: {e}")
    
    def hash_serial(self, serial_key: str) -> str:
        """產生序號雜湊"""
        return hashlib.sha256(serial_key.encode('utf-8')).hexdigest()
    
    def validate_serial(self, serial_key: str, machine_id: str, client_ip: str = "0.0.0.0") -> dict:
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
                    'error': f'設備在黑名單中: {blacklist_result[0]}',
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
    
    def revoke_serial(self, serial_key: str, reason: str = "Railway管理員停用") -> bool:
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
    
    def add_to_blacklist(self, machine_id: str, reason: str = "違規使用") -> bool:
        """加入黑名單"""
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
            print(f"加入黑名單失敗: {e}")
            return False
    
    def get_statistics(self) -> dict:
        """取得統計資訊"""
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
                'today_validations': today_validations,
                'platform': 'Railway.app',
                'server_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"取得統計失敗: {e}")
            return {'error': str(e)}
    
    def _log_validation(self, cursor, serial_hash: str, machine_id: str, 
                       validation_time: str, result: str, client_ip: str):
        """記錄驗證日誌"""
        cursor.execute('''
            INSERT INTO validation_logs 
            (serial_hash, machine_id, validation_time, result, client_ip)
            VALUES (?, ?, ?, ?, ?)
        ''', (serial_hash, machine_id, validation_time, result, client_ip))

# 建立Flask應用
app = Flask(__name__)
CORS(app)

# 初始化伺服器管理器
server_manager = RailwayServerManager()

@app.route('/')
def home():
    stats = server_manager.get_statistics()
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BOSS檢測器 Railway 驗證伺服器</title>
        <meta charset="utf-8">
        <style>
            body { font-family: Arial; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
            .status { padding: 15px; margin: 10px 0; border-radius: 5px; background: #d4edda; color: #155724; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #f2f2f2; }
            .badge { background: #007bff; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ BOSS檢測器 Railway 驗證伺服器</h1>
            <div class="status">
                ✅ 伺服器運行正常 - Railway.app 部署 - {{ current_time }}
            </div>
            
            <h2>📊 伺服器狀態</h2>
            <table>
                <tr><th>項目</th><th>狀態</th></tr>
                <tr><td>部署平台</td><td><span class="badge">Railway.app</span></td></tr>
                <tr><td>總序號數</td><td>{{ stats.total_serials }}</td></tr>
                <tr><td>活躍序號</td><td>{{ stats.active_serials }}</td></tr>
                <tr><td>停用序號</td><td>{{ stats.revoked_serials }}</td></tr>
                <tr><td>黑名單數</td><td>{{ stats.blacklist_count }}</td></tr>
                <tr><td>今日驗證</td><td>{{ stats.today_validations }}</td></tr>
            </table>
            
            <h2>🔗 API端點</h2>
            <div style="background: #f8f9fa; padding: 15px; border-radius: 5px;">
                <strong>驗證序號:</strong> POST /api/validate<br>
                <strong>停用序號:</strong> POST /api/revoke<br>
                <strong>加入黑名單:</strong> POST /api/blacklist<br>
                <strong>取得統計:</strong> GET /api/stats<br>
                <strong>健康檢查:</strong> GET /api/health
            </div>
            
            <p style="text-align: center; color: #666; margin-top: 30px;">
                BOSS檢測器 Railway 部署版 | 聯繫: @yyv3vnn
            </p>
        </div>
    </body>
    </html>
    ''', current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), stats=stats)

@app.route('/api/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'platform': 'Railway.app',
        'timestamp': datetime.now().isoformat(),
        'version': 'Railway-1.0'
    })

@app.route('/api/validate', methods=['POST'])
def validate_serial():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'valid': False, 'error': '無效的請求資料'}), 400
        
        serial_key = data.get('serial_key')
        machine_id = data.get('machine_id')
        
        if not serial_key or not machine_id:
            return jsonify({'valid': False, 'error': '缺少必要參數'}), 400
        
        client_ip = request.remote_addr or '0.0.0.0'
        result = server_manager.validate_serial(serial_key, machine_id, client_ip)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'valid': False, 'error': f'驗證失敗: {str(e)}'}), 500

@app.route('/api/revoke', methods=['POST'])
def revoke_serial():
    try:
        data = request.get_json()
        admin_key = data.get('admin_key')
        
        if admin_key != server_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        serial_key = data.get('serial_key')
        reason = data.get('reason', 'Railway管理員停用')
        
        success = server_manager.revoke_serial(serial_key, reason)
        
        return jsonify({
            'success': success,
            'message': '序號停用成功' if success else '序號停用失敗'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/blacklist', methods=['POST'])
def add_blacklist():
    try:
        data = request.get_json()
        admin_key = data.get('admin_key')
        
        if admin_key != server_manager.admin_key:
            return jsonify({'success': False, 'error': '管理員認證失敗'}), 403
        
        machine_id = data.get('machine_id')
        reason = data.get('reason', '違規使用')
        
        success = server_manager.add_to_blacklist(machine_id, reason)
        
        return jsonify({
            'success': success,
            'message': '黑名單新增成功' if success else '黑名單新增失敗'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    try:
        stats = server_manager.get_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Railway 自動提供 PORT 環境變數
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)