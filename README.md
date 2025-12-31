# Z-VulnScan Professional Edition v2.1
### 🛡️ Network Asset Discovery & Security Visibility Tool

![Version](https://img.shields.io/badge/Version-v2.1_Professional-blue?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.13+-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows_%7C_Linux-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square)

**Z-VulnScan Professional**은 인가된 네트워크 환경에서  
**자산 가시화, 포트 노출 현황 파악, 서비스 배너 수집**을 통해  
보안 담당자가 **사전 위험 요소를 식별하고 점검 결과를 문서화**할 수 있도록 지원하는  
**보안 가시화(Security Visibility) 및 사전 점검 도구**입니다.

본 도구는 **침투 테스트(PT) 또는 공격 도구가 아니며**,  
보안 정책 수립, 교육, 내부 점검, 감사 대응을 위한 **보조 수단**으로 설계되었습니다.

---

## 📑 목차 (Table of Contents)

1. [🔐 법적 고지 및 윤리 규정](#-legal--ethical-notice-중요)
2. [🎯 권장 사용 목적](#-intended-use-권장-사용-목적)
3. [🚀 주요 기능 (v2.1 Update)](#-key-features-v21-update)
4. [📂 프로젝트 구조](#-project-structure)
5. [✅ 지원 진단 항목 (KISA)](#-supported-audit-list-kisa)
6. [📸 스크린샷](#-screenshots)
7. [🛠 기술 스택](#-technology-stack)
8. [🗓 로드맵](#-roadmap)
9. [📜 라이선스](#-license)

---

## 🔐 Legal & Ethical Notice (중요)

> ⚠ **[경고] 본 프로그램은 반드시 인가된 자산 및 네트워크 환경에서만 사용해야 합니다.**

- 본 도구는 **네트워크 포트 스캔, 서비스 정보 수집, OS 설정 진단 기능**을 포함합니다.
- 사전 허가 없이 제3자의 네트워크 또는 시스템을 스캔하는 행위는  
  **정보통신망법 등 관련 법률**에 의해 **형사·민사 책임**이 발생할 수 있습니다.
- 사용자는 본 도구 사용에 따른 **모든 법적 책임을 스스로 부담**합니다.
- **실행 절차:** 최초 실행 시 **법적 고지 동의(Disclaimer Dialog)** 완료 후 기능 활성화
- **시스템 권한:** 패킷 제어를 위해 **관리자 권한**, 결과 저장을 위해 **파일 쓰기 권한** 필요

---

## 🎯 Intended Use (권장 사용 목적)

**Z-VulnScan Professional**은 다음과 같은 환경에 최적화되어 있습니다.

| ✅ 권장 용도 | ❌ 금지된 용도 |
|---|---|
| 내부 네트워크 자산 식별 및 현황 파악 | 침투 테스트 (Exploit 기반 공격) |
| 서버/서비스 노출 포트 및 배너 점검 | 무차별 외부 네트워크 스캔 |
| 보안 감사 전 사전 점검 | 서비스 거부 공격 (DoS) |
| 보안 교육 및 실습 환경 | 비인가 자산 접근 |
| PDF / Excel 보고서 자동화 |  |

---

## 🚀 Key Features (v2.1 Update)

### 1. 🛡️ Enterprise-Grade Security

- **Secure Credential Storage**  
  `keyring` 라이브러리를 활용한 OS Native 자격증명 저장소 사용  
  (Windows Credential Manager)

- **Zero-Trust Memory**  
  Just-In-Time 방식 자격증명 호출  
  사용 즉시 메모리 파기(Wiping) 처리

---

### 2. 📡 Network Asset Discovery & Safety

- **Full Scan Safety Guard**  
  1–65535 전체 포트 스캔 시  
  네트워크 부하 및 시간 경고를 위한 **2단계 경고 UI**

- **Protocol Discovery**  
  ICMP Ping 및 ARP Scan 기반 고속 자산 식별

---

### 3. 🖱️ Smart Operation UX

- **Context Menu Integration**  
  - RDP 연결  
  - SSH 접속  
  - Ping Test  
  - IP 복사

- **Input Locking**  
  스캔 중 설정 변경 방지

- **Friendly Error Masking**  
  내부 오류 발생 시 Raw Error 대신 사용자 가이드 메시지 출력

---

### 4. 🔍 Deep Vulnerability Audit

- **Extended Rule Set**  
  - Windows: 80+ 항목  
  - Linux: 70+ 항목  
  (KISA 주요정보통신기반시설 가이드라인 기반)

- **Remediation Guide**  
  취약점 발견 시 구체적 조치 방안 포함

- **Unicode Support**  
  CP949 환경 포함 한글 인코딩 완벽 지원

---

### 5. 📊 Professional Reporting

- **PDF Report**  
  경영진 요약 차트 + 상세 취약점 + 조치 방안

- **Excel Report**  
  필터링 가능한 자산/취약점 상세 데이터

---

## 📂 Project Structure

```
Z-VulnScan_Enterprise/
├── gui/
│   └── main_gui.py
├── core/
│   ├── advanced_scanner.py
│   ├── ssh_inspector.py
│   ├── windows_inspector.py
│   └── vuln_matcher.py
├── utils/
│   ├── db_connector.py
│   ├── secure_storage.py
│   └── os_utils.py
├── output/
│   ├── pdf_report.py
│   └── excel_report.py
├── rules/
│   ├── linux_rules.json
│   └── windows_rules.json
└── install_deps.py
```
## ✅ Supported Audit List (KISA)

> ℹ 인증 정보(SSH / WinRM)가 제공된 경우 정밀 진단 수행

### 🐧 Linux Server (70+)

- U-01: root 원격 접속 제한
- U-02: 패스워드 복잡성 설정
- U-20: Anonymous FTP 비활성화
- … (U-01 ~ U-72)

### 🪟 Windows Server (80+)

- W-01: Administrator 계정 이름 변경
- W-08: 기본 공유(C$, Admin$) 제거
- W-60: 최신 핫픽스 적용
- … (W-01 ~ W-80)

---

## 📸 Screenshots

- Main Dashboard & Context Menu
- Security Warning
- PDF Report (Remediation Included)
- Excel Report

---

## 🛠 Technology Stack

- **Language:** Python 3.13+
- **GUI:** PyQt5 (Qt Designer)
- **Network:** Scapy, Socket
- **Reporting:** ReportLab, OpenPyXL
- **Security:** keyring, PyInstaller

---

## 🗓 Roadmap

### ✅ v2.1 (Professional)

- 자산 탐지 및 포트 스캔
- KISA 정밀 진단
- 자격증명 보안 저장
- UX 개선
- PDF / Excel 리포트

### 🔮 v3.0 (Enterprise)

- Headless CLI Mode
- SIEM 연동 (Syslog / CEF)
- 중앙 DB 연동
- Diff Report (변경 사항 비교)

---

## 📜 License

**Proprietary License**

Copyright © 2025 Z-VulnScan Team  
All Rights Reserved.

무단 복제, 배포, 수정, 역공학 행위는 엄격히 금지됩니다.
