# Z-Vuln-Scan: Enterprise Security Audit Platform 🛡️

![Version](https://img.shields.io/badge/Version-v1.0_MVP-blue) ![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white) ![Java](https://img.shields.io/badge/Dashboard-JSP-red) ![License](https://img.shields.io/badge/License-Proprietary-red)

**Z-Vuln Scan**은 기업 네트워크 자산을 실시간으로 탐지하고, **KISA 주요정보통신기반시설 가이드라인**에 기반하여 서버의 보안 취약점을 자동으로 진단하는 **Agentless 보안 플랫폼**입니다.

---

## 🚀 Key Features (핵심 기능)

### 1. ⚡ High-Speed Network Discovery
* **Hybrid Scanning:** ICMP Ping과 Socket Connect Scan을 결합하여 `/24` 대역을 수 초 내에 탐지.
* **OS Fingerprinting:** 패킷 TTL 분석을 통해 운영체제(Windows/Linux/Network Device) 식별.
* **Non-Blocking GUI:** 멀티스레딩(Multi-threading) 및 비동기 처리로 멈춤 없는 사용자 경험 제공.

### 2. 🔍 Automated Security Audit (KISA Standard)
* **Coverage:** 계정 관리 및 파일 권한 등 핵심 취약점 **13종(U-01 ~ U-13)** 자동 진단.
* **Agentless:** 별도의 에이전트 설치 없이 **SSH**만으로 원격 점검 수행.
* **Auth Support:** Password 방식 및 **SSH Private Key**(.pem) 인증 완벽 지원.
* **Smart Simulation:** 타겟 서버 부재 시에도 기능 테스트가 가능한 **시뮬레이션 모드** 탑재.

### 3. 📊 Visualization & Reporting
* **Web Dashboard:** Java(JSP) 기반의 실시간 관제 대시보드 (Chart.js 적용).
* **One-Click Report:** 진단 즉시 경영진 보고용 **PDF 리포트(한글 지원)** 자동 생성.

---

## 🛠️ System Architecture

```
Asset-Watch/
├── scanner_engine/           # [Python] 핵심 엔진
│   ├── core/
│   │   ├── advanced_scanner.py  # 하이브리드 스캔 & OS 탐지
│   │   ├── ssh_inspector.py     # SSH 기반 취약점 진단 (U-01~13)
│   │   └── audit_runner.py      # 통합 실행 모듈
│   ├── gui/
│   │   └── main_gui.py          # PyQt5 제어 패널 (Control Tower)
│   └── output/
│       └── pdf_report.py        # PDF 리포트 생성기 (한글 폰트 내장)
├── webapp/                   # [Java] 웹 대시보드
│   └── dashboard.jsp         # 실시간 통계 및 차트
└── database/                 # [MySQL] 데이터베이스
    └── schema.sql            # 테이블 정의서

```
## 💻 Installation & Usage
### Prerequisites
- Python3.10+, MySQL 8.0+, Java JDK & Tomcat 9.01. Python Engine Setup
- (scapy, paramiko, mysql-connector-python, PyQt5, reportlab, python-dotenv)

## 실행
- python scanner_engine/gui/main_gui.py
### 2. Web Dashboard Setup
- Eclipse 등에서 Dynamic Web Project 생성.
- webapp/dashboard.jsp 파일을 프로젝트에 추가.
- WEB-INF/lib 폴더에 mysql-connector-j-8.x.jar 추가.
- Tomcat 서버 구동 후 http://localhost:8080/ProjectName/dashboard.jsp 접속
- ✅ Supported Audit List (KISA)
- U-01root 원격 접속 제한 PermitRootLogin 설정 점검
- U-02패스워드 복잡성pwquality.conf 설정 점검
- U-03계정 잠금 임계값pam_tally2/faillock 설정 점검
- U-04패스워드 파일 보호/etc/shadow 암호화 여부
- U-05PATH 환경변수"." 경로 포함 여부 점검
- U-06 ~ U-13파일/디렉터리 권한주요 설정 파일 소유자 및 권한 진단

### 📝 허가받지 않은 네트워크에 대한 스캔은 법적 책임을 질 수 있습니다.

## 라이선스
본 프로젝트는 **Proprietary License** (독점 라이선스)로 배포됩니다.  
소스코드 공개 및 재배포를 금지하며, 상용 이용 시 별도 계약이 필요합니다.  
Copyright (c) 2025 rorena15