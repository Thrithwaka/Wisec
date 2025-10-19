#!/usr/bin/env python3
"""
Create test database with sample data for Risk Summary testing
"""
import sqlite3
from datetime import datetime, timedelta
import json
import uuid

def create_test_database():
    """Create test database with sample vulnerability data"""
    
    # Create database connection
    conn = sqlite3.connect('wisec_vulnerability_system.db')
    cursor = conn.cursor()

    try:
        print("Creating database tables...")
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_verified BOOLEAN DEFAULT 0,
                is_admin_approved BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                role TEXT DEFAULT 'USER',
                account_status TEXT DEFAULT 'PENDING',
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        # Scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                network_ssid TEXT NOT NULL,
                scan_id TEXT UNIQUE NOT NULL,
                scan_timestamp TIMESTAMP NOT NULL,
                scan_duration REAL,
                risk_level TEXT DEFAULT 'NORMAL',
                overall_risk_score REAL DEFAULT 0.0,
                confidence_score REAL DEFAULT 0.0,
                scan_type TEXT DEFAULT 'standard',
                scan_status TEXT DEFAULT 'PENDING',
                model_predictions TEXT,
                ensemble_result TEXT,
                scan_data TEXT,
                network_topology TEXT,
                device_inventory TEXT,
                ip_address TEXT,
                location_data TEXT,
                scan_parameters TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Vulnerability reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_result_id INTEGER NOT NULL,
                vulnerability_type TEXT NOT NULL,
                threat_category TEXT NOT NULL,
                severity_level TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                technical_details TEXT,
                cvss_score REAL,
                risk_score REAL NOT NULL,
                confidence_level REAL NOT NULL,
                detected_by_model TEXT,
                model_confidence REAL,
                recommendations TEXT,
                remediation_steps TEXT,
                remediation_priority TEXT,
                affected_components TEXT,
                evidence_data TEXT,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_result_id) REFERENCES scan_results (id)
            )
        ''')
        
        print("Database tables created successfully")
        
        # Create test user
        cursor.execute('''
            INSERT OR REPLACE INTO users (id, email, password_hash, is_verified, is_admin_approved, role, account_status)
            VALUES (1, 'testuser@example.com', 'hashed_password', 1, 1, 'USER', 'ACTIVE')
        ''')
        
        # Create test scan results for different scenarios
        current_time = datetime.now()
        
        test_scans = [
            {
                'id': 1,
                'user_id': 1,
                'network_ssid': 'TestNetwork-Vulnerable',
                'scan_id': f'SCAN_{current_time.strftime("%Y%m%d_%H%M%S")}_001',
                'scan_timestamp': (current_time - timedelta(hours=1)).isoformat(),
                'risk_level': 'HIGH_RISK',
                'overall_risk_score': 8.5,
                'confidence_score': 0.92,
                'scan_status': 'COMPLETED',
                'scan_type': 'deep'
            },
            {
                'id': 2,
                'user_id': 1,
                'network_ssid': 'TestNetwork-Safe',
                'scan_id': f'SCAN_{current_time.strftime("%Y%m%d_%H%M%S")}_002',
                'scan_timestamp': (current_time - timedelta(hours=2)).isoformat(),
                'risk_level': 'NORMAL',
                'overall_risk_score': 2.1,
                'confidence_score': 0.87,
                'scan_status': 'COMPLETED',
                'scan_type': 'deep'
            },
            {
                'id': 3,
                'user_id': 1,
                'network_ssid': 'CurrentNetwork',
                'scan_id': f'SCAN_{current_time.strftime("%Y%m%d_%H%M%S")}_003',
                'scan_timestamp': (current_time - timedelta(minutes=30)).isoformat(),
                'risk_level': 'LOW_RISK',
                'overall_risk_score': 4.2,
                'confidence_score': 0.78,
                'scan_status': 'COMPLETED',
                'scan_type': 'deep'
            }
        ]
        
        for scan in test_scans:
            cursor.execute('''
                INSERT OR REPLACE INTO scan_results 
                (id, user_id, network_ssid, scan_id, scan_timestamp, risk_level, 
                 overall_risk_score, confidence_score, scan_status, scan_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan['id'], scan['user_id'], scan['network_ssid'], 
                scan['scan_id'], scan['scan_timestamp'], scan['risk_level'],
                scan['overall_risk_score'], scan['confidence_score'],
                scan['scan_status'], scan['scan_type']
            ))
        
        print('Test scan results created')
        
        # Create vulnerability reports for the scans
        test_vulnerabilities = [
            {
                'scan_result_id': 1,  # High risk scan
                'vulnerability_type': 'WEP_ENCRYPTION_DETECTED',
                'threat_category': 'CRITICAL_VULNERABILITY',
                'severity_level': 'CRITICAL',
                'title': 'Weak WEP Encryption Detected',
                'description': 'Network is using deprecated WEP encryption which can be cracked within minutes',
                'cvss_score': 9.3,
                'risk_score': 9.1,
                'confidence_level': 0.95,
                'detected_by_model': 'cnn_final',
                'model_confidence': 0.93,
                'recommendations': json.dumps(['Upgrade to WPA3 encryption', 'Disable WPS', 'Change default credentials']),
                'remediation_priority': 'IMMEDIATE'
            },
            {
                'scan_result_id': 1,  # Same high risk scan
                'vulnerability_type': 'DEFAULT_CREDENTIALS',
                'threat_category': 'HIGH_RISK_VULNERABILITY',
                'severity_level': 'HIGH',
                'title': 'Default Router Credentials Detected',
                'description': 'Router appears to be using default administrative credentials',
                'cvss_score': 7.8,
                'risk_score': 8.2,
                'confidence_level': 0.88,
                'detected_by_model': 'random_forest',
                'model_confidence': 0.91,
                'recommendations': json.dumps(['Change default username/password', 'Enable two-factor authentication']),
                'remediation_priority': 'HIGH'
            },
            {
                'scan_result_id': 2,  # Normal risk scan
                'vulnerability_type': 'OUTDATED_FIRMWARE',
                'threat_category': 'LOW_RISK_VULNERABILITY',
                'severity_level': 'LOW',
                'title': 'Outdated Router Firmware',
                'description': 'Router firmware is slightly outdated but not critically vulnerable',
                'cvss_score': 3.1,
                'risk_score': 2.8,
                'confidence_level': 0.82,
                'detected_by_model': 'lstm_production',
                'model_confidence': 0.79,
                'recommendations': json.dumps(['Update router firmware when convenient']),
                'remediation_priority': 'LOW'
            },
            {
                'scan_result_id': 3,  # Low risk scan
                'vulnerability_type': 'WEAK_PASSWORD_POLICY',
                'threat_category': 'MEDIUM_RISK_VULNERABILITY',
                'severity_level': 'MEDIUM',
                'title': 'Weak WiFi Password Policy',
                'description': 'WiFi password appears to follow a predictable pattern',
                'cvss_score': 5.4,
                'risk_score': 4.7,
                'confidence_level': 0.76,
                'detected_by_model': 'gradient_boosting',
                'model_confidence': 0.81,
                'recommendations': json.dumps(['Use a stronger, randomly generated password', 'Enable WPA3 if available']),
                'remediation_priority': 'MEDIUM'
            }
        ]
        
        for vuln in test_vulnerabilities:
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerability_reports
                (scan_result_id, vulnerability_type, threat_category, severity_level, title,
                 description, cvss_score, risk_score, confidence_level, detected_by_model,
                 model_confidence, recommendations, remediation_priority)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln['scan_result_id'], vuln['vulnerability_type'], vuln['threat_category'],
                vuln['severity_level'], vuln['title'], vuln['description'],
                vuln['cvss_score'], vuln['risk_score'], vuln['confidence_level'],
                vuln['detected_by_model'], vuln['model_confidence'],
                vuln['recommendations'], vuln['remediation_priority']
            ))
        
        print('Test vulnerability reports created')
        
        # Commit the changes
        conn.commit()
        
        # Verify the data
        cursor.execute('SELECT COUNT(*) FROM scan_results')
        scan_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM vulnerability_reports')
        vuln_count = cursor.fetchone()[0]
        
        print(f'\nDatabase created successfully:')
        print(f'  - Scan results: {scan_count}')
        print(f'  - Vulnerability reports: {vuln_count}')
        
        # Show sample data
        cursor.execute('''
            SELECT sr.network_ssid, sr.risk_level, sr.overall_risk_score, COUNT(vr.id) as vuln_count
            FROM scan_results sr
            LEFT JOIN vulnerability_reports vr ON sr.id = vr.scan_result_id
            GROUP BY sr.id, sr.network_ssid, sr.risk_level, sr.overall_risk_score
            ORDER BY sr.scan_timestamp DESC
        ''')
        
        print('\nSample scan data:')
        for row in cursor.fetchall():
            print(f'  Network: {row[0]}, Risk: {row[1]}, Score: {row[2]}, Vulnerabilities: {row[3]}')
        
        return True
        
    except Exception as e:
        print(f'Database creation error: {e}')
        import traceback
        traceback.print_exc()
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    create_test_database()