# Z-Vuln-Scan: Hybrid Security Audit Tool 🛡️

![Version](https://img.shields.io/badge/Version-v2.0_Hybrid-blue) ![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white) ![Build](https://img.shields.io/badge/Build-Standalone_EXE-green) ![License](https://img.shields.io/badge/License-Proprietary-red)

**Z-Vuln Scan**은 기업 내 이기종 서버(Linux/Windows) 환경을 지원하는 **하이브리드 보안 진단 자동화 도구**입니다.
**Agentless** 방식을 채택하여 별도의 설치 없이 즉시 실행 가능하며, **KISA 주요정보통신기반시설 가이드라인**에 기반한 정밀 진단을 수행합니다.

> **v2.0 Update:** Windows 서버 진단(WinRM) 지원 및 자동 OS 식별 기능 탑재, Portable(.exe) 배포 최적화.

---

## 🚀 Key Features (핵심 기능)

### 1. ⚡ Hybrid & Smart Discovery
* **Auto OS Detection:** 포트 핑거프린팅(Port Fingerprinting)을 통해 대상 서버의 OS(Linux vs Windows)를 자동으로 식별하고 적절한 진단 모듈을 로드합니다.
* **Dual Protocol Support:**
    * 🐧 **Linux:** SSH (Port 22) 기반 무결성 점검.
    * 🪟 **Windows:** WinRM (Port 5985) 기반 PowerShell 진단.
* **High-Speed Scan:** 멀티스레딩(Multi-threading) 및 Generator 기반 메모리 최적화로 대규모 대역(/16, /24)도 안정적으로 스캔.

### 2. 🔍 KISA Standard Security Audit
* **Coverage:** KISA 가이드라인 기반의 핵심 취약점 자동 진단.
    * **Linux (U-Type):** 계정 관리, 파일 권한, 프로세스 점검 등 (U-01 ~ U-13).
    * **Windows (W-Type):** 관리자 계정 보호, 불필요한 서비스 제거 등 (W-01 ~ W-03 Beta).
* **Agentless:** 타겟 서버에 에이전트를 설치할 필요 없이, 인증 정보(ID/PW)만으로 원격 점검 수행.

### 3. 💼 Portable & Standalone
* **No Installation Required:** 내장 DB(SQLite)를 사용하여 별도의 데이터베이스 서버 구축 없이 **EXE 파일 하나로 즉시 실행**.
* **Instant Reporting:** 진단 종료 즉시 경영진 보고용 **PDF 리포트(차트 포함)** 자동 생성.
* **Simulation Mode:** 폐쇄망 환경이나 계정 정보가 없는 경우를 대비한 가상 시뮬레이션 기능 제공.

---

## 🛠️ System Architecture

```
Z-VulnScan_v2.0/
├── scanner_engine/           # [Python] 메인 엔진
│   ├── core/
│   │   ├── advanced_scanner.py  # 네트워크 스캔 & OS 탐지
│   │   ├── ssh_inspector.py     # Linux 진단 모듈 (Paramiko)
│   │   ├── audit_runner.py      # 취약점 모듈
│   │   ├── icmp_scanner.py      # ICMP 기반 활성 진단 모듈
│   │   └── windows_inspector.py # [NEW] Windows 진단 모듈 (PyWinRM)
│   ├── gui/
│   │   └── main_gui.py          # 통합 제어 패널 (PyQt5) & Smart Branching
│   ├── utils/
│   │   ├── check_db.py          # DB 점검 스크립트
│   │   └── db_connector.py      # SQLite 내장 DB 핸들러 (Auto-Init)
│   └── output/
│       └── pdf_report.py        # 리포트 생성기 (ReportLab)
└── zvuln_scan.db             # [SQLite] 로컬 데이터 저장소 (자동 생성)
```

## 💻 Installation & Usage

### 1. Standalone Execution (권장)
- 별도의 파이썬 설치 없이, 배포된 실행 파일(`Z-VulnScan.exe`)을 관리자 권한으로 실행하십시오.
- (Windows/Linux 스캔을 위해 네트워크 방화벽 오픈 필요: TCP 22, 5985)

### 2. Run from Source (개발자용)
#### Prerequisites
- Python 3.10+
- `pip install scapy paramiko pyqt5 reportlab pywinrm`
- (Windows 실행 시 Npcap 설치 권장)

#### 실행 명령어
```
python scanner_engine/gui/main_gui.py
```
## ✅ Supported Audit List (KISA)

- 🐧 Linux Server (Unix 계열)

|  코드 | 항목명              | 주요 점검 내용                        |
|--------|---------------------|---------------------------------------|
| U-01 | root 원격 접속 제한 | sshd_config PermitRootLogin 설정 점검 |
| U-02 | 패스워드 복잡성     | pwquality.conf 설정 점검              |
| U-03 | 계정 잠금 임계값    | pam_tally2/faillock 설정 점검         |
|  ...  | ...                 | ...                                   |
|  U-13 | SUID/SGID 설정      | 주요 시스템 파일의 권한 설정 진단     |

- 🪟 Windows Server (New!)

| 코드 | 항목명             | 주요 점검 내용                                |
|------|--------------------|-----------------------------------------------|
| W-01 | Administrator 계정 | 이름기본 관리자 계정 이름 변경 및 활성화 여부 |
| W-02 | Guest 계정 상태    | Guest 계정 비활성화 여부 점검                 |
| W-03 | 불필요한 서비스    | Telnet, FTP 등 취약한 서비스 실행 여부        |

##🔮 Future Roadmap (Enterprise)
- v3.0: Centralized Management (MySQL/MariaDB 연동 지원).
- Web Dashboard: Java(JSP) 기반의 웹 관제 콘솔 제공 (Optional).
- CVE Scan: NVD 데이터베이스 연동을 통한 버전 기반 취약점(CVE) 스캔.
###📝 License & Warning허가받지 않은 네트워크에 대한 스캔은 법적 책임을 질 수 있습니다. 본 도구는 인가된 자산에 대해서만 사용하십시오.Proprietary License: Copyright (c) 2025 rorena15. All rights reserved.
