-- 데이터베이스 생성
CREATE DATABASE asset_watch_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE asset_watch_db;

-- 1. 자산 정보 테이블 (TBL_ASSETS) 생성 [cite: 136, 137]
CREATE TABLE TBL_ASSETS (
    asset_id INT AUTO_INCREMENT PRIMARY KEY COMMENT '자산 고유 ID',
    ip_addr VARCHAR(45) NOT NULL COMMENT 'IPv4/IPv6 주소',
    mac_addr VARCHAR(17) COMMENT 'MAC 주소 (ARP 스캔 결과)',
    hostname VARCHAR(255) COMMENT '호스트명',
    os_type VARCHAR(50) COMMENT '운영체제 유형 (Windows, Linux, etc.)',
    os_version VARCHAR(100) COMMENT '운영체제 상세 버전',
    dept_code VARCHAR(50) COMMENT '관리 부서 코드',
    asset_value DECIMAL(15, 2) DEFAULT 0 COMMENT '자산 가치 (ROSI 계산용)',
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '최초 발견 시각',
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '최근 식별 시각',
    
    -- 인덱스 설정: IP 조회 성능 향상
    UNIQUE INDEX idx_ip_addr (ip_addr)
);

-- 확인용 더미 데이터 입력
INSERT INTO TBL_ASSETS (ip_addr, hostname, os_type, asset_value) 
VALUES ('192.168.0.10', 'DB-Main-Svr', 'Linux', 10000000);
-- 2. 열린 포트 테이블
CREATE TABLE TBL_OPEN_PORTS (
    port_id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    port_number INT NOT NULL,
    banner VARCHAR(255),
    scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES TBL_ASSETS(asset_id) ON DELETE CASCADE,
    UNIQUE KEY uk_port (asset_id, port_number)
);

-- 3. 취약점 정의 테이블 (KISA 등)
CREATE TABLE TBL_VULN_DEF (
    vuln_id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(20) NOT NULL UNIQUE,          -- e.g. 'U-01'
    title VARCHAR(255) NOT NULL,
    severity ENUM('HIGH', 'MEDIUM', 'LOW') NOT NULL,
    description TEXT,
    remediation TEXT
);

-- 4. 스캔 결과 테이블
CREATE TABLE TBL_SCAN_RESULT (
    result_id INT AUTO_INCREMENT PRIMARY KEY,
    asset_id INT NOT NULL,
    vuln_id INT NOT NULL,
    status ENUM('SAFE', 'VULNERABLE', 'WARNING', 'ERROR') NOT NULL,
    detected_value TEXT,
    scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES TBL_ASSETS(asset_id) ON DELETE CASCADE,
    FOREIGN KEY (vuln_id) REFERENCES TBL_VULN_DEF(vuln_id)
);

-- 초기 취약점 정의 데이터 (현재 U-01만)
INSERT INTO TBL_VULN_DEF (code, title, severity, description) 
VALUES ('U-01', 'root 계정 원격 접속 제한', 'HIGH', 'PermitRootLogin no 설정 여부');