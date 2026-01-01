# Z-VulnScan Professional Edition v3.0.0
### 🛡️ Network Asset Discovery & Security Visibility Tool

![Version](https://img.shields.io/badge/Version-v3.0.0_Professional-blue?style=flat-square) ![Python](https://img.shields.io/badge/Python-3.13+-3776AB?style=flat-square&logo=python&logoColor=white) ![Platform](https://img.shields.io/badge/Platform-Windows_%7C_Linux-lightgrey?style=flat-square) ![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square)

**Z-VulnScan Professional Edition v3.0.0**은 기존 v2.2.0의 안정성을 계승함과 동시에, 대규모 네트워크 환경에서의 **가시성(Visibility)과 처리 성능을 극대화**한 메이저 업데이트 버전입니다. 새롭게 도입된 **Interactive Topology Map**과 **Batch Update Engine**을 통해 수백 대의 자산을 렉(Lag) 없이 실시간으로 시각화하며, 정밀한 보안 감사 환경을 제공합니다.

본 도구는 **침투 테스트(PT) 또는 공격 도구가 아니며**, 보안 정책 수립, 교육, 내부 점검, 감사 대응을 위한 **보조 수단**으로 설계되었습니다.

---

## 📑 목차 (Table of Contents)
1. [🔐 법적 고지 및 윤리 규정](#-legal--ethical-notice-중요)
2. [🎯 권장 사용 목적](#-intended-use-권장-사용-목적)
3. [🚀 주요 기능](#-key-features)
4. [✅ 지원 진단 항목 (KISA)](#-supported-audit-list-kisa)
5. [📸 스크린샷](#-screenshots)
6. [🛠 기술 스택](#-technology-stack)
7. [🗓 로드맵](#-roadmap)
8. [📜 라이선스](#-license)

---

## 🔐 Legal & Ethical Notice (중요)

> ⚠ **[경고] 본 프로그램은 반드시 인가된 자산 및 네트워크 환경에서만 사용해야 합니다.**

- 본 도구는 **네트워크 포트 스캔, 서비스 정보 수집, OS 설정 진단 기능**을 포함합니다.
- 사전 허가 없이 제3자의 네트워크 또는 시스템을 스캔하는 행위는 **정보통신망법 등 관련 법률**에 의해 **형사·민사 책임**이 발생할 수 있습니다.
- 사용자는 본 도구 사용에 따른 **모든 법적 책임을 스스로 부담**합니다.
- **실행 절차:** 프로그램 최초 실행 시, 위 사항에 대한 **법적 고지 동의(Disclaimer Dialog)** 과정을 거쳐야만 기능이 활성화됩니다.

---

## 🎯 Intended Use (권장 사용 목적)

**Z-VulnScan Professional**은 다음과 같은 운영 환경에 최적화되어 있습니다.

| ✅ 권장 용도 | ❌ 금지된 용도 |
|---|---|
| • 내부 네트워크 **자산 식별 및 현황 파악** | • 침투 테스트 (Exploit 기반 공격) |
| • 서버/서비스 **노출 포트 및 배너 점검** | • 무차별 외부 네트워크 스캔 (Scanning) |
| • 보안 감사 전 **사전 점검(Pre-audit Checklist)** | • 서비스 거부 공격 (DoS) 시뮬레이션 |
| • 보안 교육 및 실습 환경 구축 | • 타인 소유 자산에 대한 비인가 접근 |
| • 점검 결과 **보고서(PDF/Excel) 자동화** | |

---

## 🚀 Key Features

### 1. 📡 Network Asset Discovery
- **ICMP Ping:** 활성 호스트의 신속한 생존 여부 탐지
- **ARP Scan:** 내부 네트워크 대역(L2)의 정밀한 자산 식별
- 인가된 로컬 네트워크 환경에 최적화된 스캔 엔진

### 2. 🔍 Port Exposure Scanning
- **Fast Scan:** 주요 Well-known 포트(Top 100) 빠른 점검
- **Full Scan:** 전체 포트(1-65535) 대상 정밀 노출 현황 분석
- **Custom Scan:** 사용자 정의 포트 범위 지정 가능
- **Scan Mode:** TCP Connect / TCP SYN Scan 모드 지원 (*관리자 권한 필요*)

### 3. 🏷️ Service Banner Collection
- 서비스 데몬의 배너 정보 수집 및 분석
- 소프트웨어 버전 및 서비스 유형 식별
- **Note:** CVE 직접 탐지 기능은 제공하지 않으며, 참고용 보안 정보(Reference)만 매핑합니다.

### 4. 📊 Professional Reporting
- **Excel Report (.xlsx):** 자산 목록, 포트 현황, 상세 진단 결과를 필터링 가능한 형태로 제공
- **PDF Report (.pdf):** 경영진 보고 및 감사 대응을 위한 요약/상세 통합 문서 자동 생성
- **Visual Alert:** 취약/경고 항목에 대한 시각적 강조 처리

### 5. 💻 Modern GUI Dashboard
- **PySide6 기반 다크 모드 UI:** 장시간 분석 업무에 최적화
- **Real-time Status:** 진행률(Progress Bar), 남은 시간(ETA) 제공
- **Input Validation:** IP/Port 입력값 검증 및 오동작 방지 로직 적용
- **Smart Log Console:** 실시간 로그 출력 및 1,000줄 자동 정리 기능을 통한 장시간 가동 안정성 확보
### 6. 🗺️ Interactive Topology Map (v3.0 New)
- **Visual Visibility:** 스캔된 자산을 중앙 제어 도구 중심으로 시각화하여 네트워크 구조도 제공
- **Dynamic Control:** 마우스 휠(Zoom) 및 드래그(Pan)를 지원하는 인터랙티브 다크 테마 맵
- **Snapshot:** 현재 구성된 네트워크 맵을 고해상도 PNG 이미지로 즉시 저장 기능 지원

---

## ✅ Supported Audit List (KISA)

> ℹ **[참고]** 아래 항목은 대상 자산에 대한 **SSH/WinRM 인증 정보**가 제공된 경우 정밀 진단됩니다. v2.1에서 진단 항목이 대폭 확장되었습니다.

### 🐧 Linux Server (Unix 계열) - 70+ Items
| 코드 | 항목명 | 주요 점검 내용 |
|:---:|---|---|
| **U-01** | root 원격 접속 제한 | `sshd_config` 내 PermitRootLogin 설정 점검 |
| **U-02** | 패스워드 복잡성 설정 | `pwquality.conf` 등 암호 정책 설정 점검 |
| **U-20** | Anonymous FTP 비활성화 | 익명 FTP 접속 허용 여부 점검 |
| ... | ... | (U-01 ~ U-72 항목 지원) |

### 🪟 Windows Server - 80+ Items
| 코드 | 항목명 | 주요 점검 내용 |
|:---:|---|---|
| **W-01** | Administrator 계정 이름 변경 | 기본 관리자 계정명 변경 여부 |
| **W-08** | 하드디스크 기본 공유 제거 | C$, Admin$ 등 기본 공유 활성화 여부 |
| **W-60** | 최신 핫픽스 적용 | Windows 보안 업데이트 적용 상태 점검 |
| ... | ... | (W-01 ~ W-80 항목 지원) |

---

## 📸 Screenshots

| **Main Dashboard & Context Menu** | **Security Warning** |
|:---:|:---:|
| <img src="img/dashboard.png" width="400" alt="Main GUI"> | <img src="img/Warnning.png" width="400" alt="Warning GUI"> |
| **PDF Report (Remediation Included)** | **Excel Report** |
| <img src="img/report.png" width="400" alt="PDF Report"> | <img src="img/report_excel.png" width="400" alt="Excel Report"> |
| **Network Topology map** |
| <img src="img/map.png" width="400" alt="PDF Report"> | 

---

## 🛠 Technology Stack

- **Language:** Python 3.13+ (Optimized with Cython)
- **GUI Framework:** PySide6 (Qt for Python)
- **Graph Engine:** NetworkX & Matplotlib (High-Performance Rendering)
- **Network Engine:** Python Native Socket (`socket`, `struct` Lib only)
- **Reporting Engine:** ReportLab (PDF), OpenPyXL (Excel)
- **Database:** SQLite (Embedded for Local Asset Management)

---

## 🗓 Roadmap

### ✅ v3.0.0 (Current - Professional Edition)
- [x] **Visualization:** Interactive Topology Map (Dark Theme) 탑재
- [x] **Performance:** Batch Update & Memory Caching 시스템 도입 (UI 렉 해결)
- [x] **GUI:** 로그 콘솔 최적화 및 3.0 전용 UI 리마스터
- [x] **Stability:** PySide6 표준 문법 전면 적용 및 크래시 방지 로직 강화

### 🔮 v3.5.0 (Future - Enterprise)
- [ ] **Headless Mode:** CLI 지원을 통한 스케줄러(Cron) 연동 및 자동화
- [ ] **SIEM Integration:** Syslog/CEF 포맷 로그 전송 기능
- [ ] **Centralized DB:** 로컬 SQLite를 넘어 MySQL/PostgreSQL 중앙 저장소 연동
- [ ] **Diff Report:** 지난 진단 결과와의 변동 사항(New/Fixed) 비교 리포트

---

## 📜 License

**Proprietary License**

Copyright © 2026 **Z-VulnScan Team**. All Rights Reserved.

본 소프트웨어는 **상용/비공개 소프트웨어**입니다. 저작권자의 사전 서면 허가 없이 본 소프트웨어의 전부 또는 일부를 무단으로 복제, 배포, 수정, 역공학(Reverse Engineering)하는 행위는 엄격히 금지됩니다.