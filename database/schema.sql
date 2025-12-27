CREATE DATABASE asset_watch_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE asset_watch_db;

-- TBL_ASSETS (기존)
CREATE TABLE TBL_ASSETS (
    asset_id INT AUTO_INCREMENT PRIMARY KEY,
    ip_addr VARCHAR(45) NOT NULL UNIQUE,
    mac_addr VARCHAR(17),
    hostname VARCHAR(255),
    os_type VARCHAR(50),
    os_version VARCHAR(100),
    dept_code VARCHAR(50),
    asset_value DECIMAL(15,2) DEFAULT 0,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- TBL_OPEN_PORTS
CREATE TABLE TBL_OPEN_PORTS (
    port_id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    port_number INT NOT NULL,
    banner VARCHAR(255),
    scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES TBL_ASSETS(asset_id) ON DELETE CASCADE,
    UNIQUE KEY uk_port (asset_id, port_number)
);

-- TBL_VULN_DEF (취약점 정의)
CREATE TABLE TBL_VULN_DEF (
    vuln_id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(20) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    severity ENUM('HIGH','MEDIUM','LOW') NOT NULL,
    description TEXT
);

-- TBL_SCAN_RESULT
CREATE TABLE TBL_SCAN_RESULT (
    result_id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    vuln_id INT NOT NULL,
    status ENUM('SAFE','VULNERABLE','WARNING','ERROR') NOT NULL,
    detected_value TEXT,
    scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES TBL_ASSETS(asset_id) ON DELETE CASCADE,
    FOREIGN KEY (vuln_id) REFERENCES TBL_VULN_DEF(vuln_id)
);

-- 초기 취약점 데이터 (U-01 ~ U-13)
INSERT INTO TBL_VULN_DEF (code, title, severity, description) VALUES
('U-01', 'root 계정 원격 접속 제한', 'HIGH', 'PermitRootLogin no 설정'),
('U-02', '패스워드 복잡성 설정', 'HIGH', 'pwquality.conf minlen 등'),
('U-03', '계정 잠금 정책', 'HIGH', 'pam_faillock deny=5'),
('U-04', '패스워드 파일 보호', 'HIGH', '/etc/shadow 640'),
('U-05', 'root 홈 디렉토리 권한', 'HIGH', '/root 700'),
('U-06', '빈 패스워드 계정', 'CRITICAL', 'shadow에 빈 패스워드 없음'),
('U-07', '계정 잠금 임계값', 'HIGH', 'deny=5~10'),
('U-08', '패스워드 만료 기간', 'MEDIUM', 'PASS_MAX_DAYS 90'),
('U-09', 'umask 설정', 'MEDIUM', 'umask 077'),
('U-10', '중요 파일 권한', 'HIGH', '기타 쓰기 금지'),
('U-11', 'SUID/SGID 파일 점검', 'HIGH', '과도한 SUID/SGID'),
('U-12', 'cron 파일 권한', 'HIGH', 'cron 디렉토리 700'),
('U-13', 'history 파일 권한', 'MEDIUM', '~/.bash_history 600');