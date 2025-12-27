# Asset-Watch & Audit: 자산 관리 기반 지능형 취약점 진단 플랫폼

![Project Status](https://img.shields.io/badge/Status-Prototype-blue) ![Python](https://img.shields.io/badge/Python-3.10+-yellow) ![MySQL](https://img.shields.io/badge/Database-MySQL-orange) ![License](https://img.shields.io/badge/License-Proprietary-red)

## 📖 프로젝트 개요 (Overview)
**Asset-Watch & Audit**은 기업 내부 네트워크의 **가시성(Visibility)** 확보와 **컴플라이언스(Compliance)** 대응 자동화를 목표로 하는 통합 보안 플랫폼입니다.

기존 상용 스캐너의 높은 도입 비용과 복잡성을 해결하기 위해 설계되었으며, **에이전트 설치 없는(Agentless)** 방식의 자산 식별과 **KISA 주요정보통신기반시설 취약점 가이드**에 기반한 정밀 진단을 수행합니다. 단순한 툴 사용을 넘어, **Raw Socket 레벨의 패킷 조작**과 **자동화된 감사 로직**을 직접 구현하여 기술적 깊이를 더했습니다.

---

## 🚀 핵심 기능 (Key Features)

### 1. 지능형 네트워크 스캐너 (Intelligent Scanner)
* **멀티 벡터 정찰:** 방화벽 우회를 위한 ICMP 및 TCP ACK Ping Sweep 구현 (Scapy 활용).
* **OS 핑거프린팅:** 패킷 헤더의 TTL 값을 분석하여 운영체제(Windows/Linux)를 수동적(Passive)으로 식별.
* **Stealth Port Scan:** TCP 3-Way Handshake를 완료하지 않는 SYN Scan 기법으로 로그 기록 최소화.

### 2. 자동화된 취약점 감사 (Automated Auditing)
* **Agentless Architecture:** 별도의 에이전트 설치 없이 SSH 프로토콜만으로 서버 내부 설정 점검.
* **KISA Compliance Check:** 'U-01(root 계정 원격 접속 제한)' 등 한국형 보안 가이드라인 자동 진단 로직 탑재.
* **정규화된 데이터 관리:** 자산 정보와 진단 결과를 RDBMS(MySQL)에 체계적으로 적재하여 이력 관리.

### 3. 직관적인 관제 및 리포팅 (Control & Reporting)
* **Desktop GUI:** PyQt5 기반의 실시간 스캔 제어 패널 제공 (Multi-threading 적용).
* **One-Click Reporting:** 진단 종료 즉시 경영진 보고용 PDF 리포트 자동 생성.
* **안전한 실행 환경:** Subprocess 격리 기술을 적용하여 리포팅 중 프로그램 크래시 방지.

---

## 🛠 기술 스택 (Tech Stack)

| 구분 | 기술 요소 | 활용 내용 |
| :--- | :--- | :--- |
| **Language** | Python 3.x | 핵심 스캔 엔진, GUI, 리포트 생성 모듈 개발 |
| **Network Lib** | **Scapy** | 로우 레벨 패킷 생성/조작, 프로토콜 헤더 분석 |
| **Audit Lib** | **Paramiko** | SSH 원격 접속 및 명령어 실행 자동화 |
| **GUI** | **PyQt5** | 관리자용 제어 패널 및 실시간 로그 콘솔 구현 |
| **Database** | MySQL | 자산(Asset), 취약점(Vuln), 결과(Result) 데이터 저장 |
| **Reporting** | ReportLab | 진단 결과의 동적 PDF 문서 렌더링 |

---

## 📂 프로젝트 구조 (Directory Structure)

```
Z-V_Scan/
├── scanner_engine/           # 메인 엔진 디렉터리
│   ├── core/                 # 핵심 로직 (Scanner, Auditor)
│   │   ├── advanced_scanner.py  # Scapy 기반 네트워크 스캐너
│   │   ├── ssh_inspector.py     # SSH 기반 취약점 진단기
│   │   └── audit_runner.py      # 통합 실행 모듈
│   ├── gui/                  # 사용자 인터페이스
│   │   └── main_gui.py          # PyQt5 메인 프로그램
│   ├── utils/                # 유틸리티
│   │   └── db_connector.py      # DB 연결 및 쿼리 처리
│   └── output/               # 결과물 저장소
│       └── pdf_report.py        # PDF 리포트 생성기
├── database/                 # 데이터베이스 스크립트
│   └── schema.sql            # 테이블 생성 SQL
└── README.md                 # 프로젝트 설명서
```

## 💻 설치 및 실행 (Installation & Usage)
### 1. 필수 요구사항 (Prerequisites)
- Python 3.10 이상
- MySQL Server 8.0 이상
- Npcap (Windows 환경에서 Scapy 사용 시 필수)

### 2. 라이브러리 설치

- pip install scapy paramiko mysql-connector-python PyQt5 reportlab
### 3. 데이터베이스 설정
- MySQL에 접속하여 database/schema.sql을 실행하거나 아래 명령어로 DB를 초기화합니다. (초기 관리자 계정: root / password - utils/db_connector.py에서 수정 필요)

### 4. 프로그램 실행

- python scanner_engine/gui/main_gui.py
- Network Scan: IP 입력 후 파란색 버튼 클릭 (자산 식별)

- Audit Scan: IP/ID/PW 입력 후 빨간색 버튼 클릭 (취약점 진단)

- Report: 초록색 버튼 클릭 (PDF 생성)

### 📊 시스템 아키텍처 (Architecture)
코드 스니펫

graph TD
    User[관리자] -->|GUI Control| Engine[Python Scanner Engine]
    Engine -->|Packet Injection| Network[사내 네트워크]
    Engine -->|SSH Access| Server[타겟 서버]
    
    Engine -->|Save Data| DB[(MySQL Database)]
    DB -->|Query Data| Reporter[PDF Report Module]
    Reporter -->|Generate| PDF[보안 진단 보고서]
### 🔮 향후 로드맵 (Roadmap)
[x] Phase 1: 스캐너 코어 및 DB 연동 구현 (완료)

[x] Phase 2: GUI 제어 패널 및 PDF 리포팅 구현 (완료)

[ ] Phase 3: 웹 대시보드(Web Dashboard) 구축 (진행 예정)

[ ] Phase 4: ROSI(보안 투자 대비 효과) 분석 알고리즘 탑재

[ ] Phase 5: AI(LLM) 기반 조치 가이드 자동 생성 연동

### 📝 라이선스 및 정보
- Author: [rorena15]

- Contact: [rorena1586@gmail.com]

- Note: 본 프로젝트는 허가된 네트워크 및 시스템에서만 테스트해야 하며, 불법적인 용도로의 사용을 금합니다.


---
