# Z-VulnScan Professional Edition v2.2.0
### 🛡️ Portable Network Asset Discovery & Security Visibility Tool

![Version](https://img.shields.io/badge/Version-v2.2.0_Stable-blue?style=flat-square) ![Python](https://img.shields.io/badge/Python-3.13+-3776AB?style=flat-square&logo=python&logoColor=white) ![Platform](https://img.shields.io/badge/Platform-Windows_%7C_Linux-lightgrey?style=flat-square) ![License](https://img.shields.io/badge/License-Proprietary-red?style=flat-square)

**Z-VulnScan Professional v2.2.0**은 외부 드라이버(Npcap/WinPcap) 설치 없이 **순수 소켓(Native Socket) 기술**을 기반으로 작동하는 **무설치(Portable) 보안 가시화 및 취약점 진단 도구**입니다. 폐쇄망(OT) 및 인터넷이 제한된 환경에서도 **시스템 변경 없이(Registry Clean)** 자산 식별, 포트 점검, 취약점 진단을 수행하고 결과를 즉시 문서화할 수 있습니다.

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

- 본 도구는 **네트워크 패킷 생성, 서비스 정보 수집, OS 설정 진단 기능**을 포함합니다.
- 사전 허가 없이 제3자의 네트워크 또는 시스템을 스캔하는 행위는 **정보통신망법 등 관련 법률**에 의해 **형사·민사 책임**이 발생할 수 있습니다.
- 사용자는 본 도구 사용에 따른 **모든 법적 책임을 스스로 부담**합니다.
- **실행 절차:** 프로그램 최초 실행 시, 위 사항에 대한 **법적 고지 동의(Disclaimer Dialog)** 과정을 거쳐야만 기능이 활성화됩니다.

---

## 🎯 Intended Use (권장 사용 목적)

**Z-VulnScan Professional**은 외부망 접속이 차단되거나 가용성이 중요한 운영 환경에 최적화되어 있습니다.

| ✅ 권장 용도 | ❌ 금지된 용도 |
|---|---|
| • **폐쇄망/OT 환경** 내부 자산 식별 | • 침투 테스트 (Exploit 기반 공격) |
| • 노후 서버(Legacy) **안전 진단(Fail-Safe)** | • 무차별 외부 네트워크 스캔 (Scanning) |
| • 보안 감사 전 **사전 점검(Pre-audit Checklist)** | • 서비스 거부 공격 (DoS) 시뮬레이션 |
| • 별도 설치가 불가능한 환경의 **USB 구동** | • 타인 소유 자산에 대한 비인가 접근 |
| • 점검 결과 **보고서(PDF/Excel) 자동화** | |

---

## 🚀 Key Features

### 1. 📡 Dependency-Free Discovery
- **Native Engine:** Npcap 등 별도 드라이버 설치 없이 OS 표준 소켓만으로 스캔 수행
- **System Safe:** 레지스트리를 오염시키지 않아 블루스크린(BSOD) 위험 원천 차단
- **Portable:** USB 연결 즉시 실행 가능한 단일 실행 파일(.exe) 제공

### 2. 🔍 Hybrid Port Scanning
- **Fast Mode:** 주요 Well-known 포트(Top 100) 대상 고속 스캔
- **Hybrid Engine:** ICMP Echo와 TCP Connect 방식을 혼합하여 탐지 정확도 향상
- **Fail-Safe Architecture:** 스캔 중 좀비 프로세스 방지 및 소켓 자원 자동 회수 로직 탑재
- **Performance:** 멀티스레딩 최적화를 통해 C클래스 대역 고속 진단

### 3. 🏷️ Service Banner & OS Detection
- 서비스 데몬의 배너 그래빙(Banner Grabbing) 및 버전 정보 분석
- TTL 값을 기반으로 한 원격 호스트 OS(Windows/Linux) 추정
- **Note:** CVE 직접 탐지 기능은 제공하지 않으며, 참고용 보안 정보(Reference)만 매핑합니다.

### 4. 📊 One-Click Reporting
- **Excel Report (.xlsx):** 엔지니어 분석용 로우 데이터(Raw Data) 및 필터링 시트 제공
- **PDF Report (.pdf):** 경영진 보고용 요약 차트 및 상세 취약점 내역 자동 생성
- **Instant Gen:** 진단 종료와 동시에 별도 변환 작업 없이 리포트 즉시 출력

### 5. 💻 Modern GUI Dashboard
- **PySide6 기반 UI:** 고해상도(HiDPI) 지원 및 직관적인 다크 모드 인터페이스
- **Real-time Console:** 스캔 진행 상황 및 에러 로그 실시간 모니터링
- **Input Validation:** 잘못된 IP 대역 입력 방지 및 예외 처리 강화

---

## ✅ Supported Audit List (KISA)

> ℹ **[참고]** 아래 항목은 대상 자산에 대한 **SSH/WinRM 인증 정보**가 제공된 경우 정밀 진단됩니다. KISA 주요 정보통신기반시설 취약점 가이드라인을 준수합니다.

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

| **Main Dashboard (v2.2.0)** | **Scan Configuration** |
|:---:|:---:|
| <img src="img/dashboard_v2.png" width="400" alt="Main GUI"> | <img src="img/config_v2.png" width="400" alt="Config GUI"> |
| **PDF Report (Auto-Generated)** | **Excel Report** |
| <img src="img/report_v2.png" width="400" alt="PDF Report"> | <img src="img/excel_v2.png" width="400" alt="Excel Report"> |

---

## 🛠 Technology Stack

- **Language:** Python 3.13+ (Optimized with Cython)
- **GUI Framework:** PySide6 (Qt for Python)
- **Network Engine:** Python Native Socket (`socket`, `struct` Lib only)
- **Reporting Engine:** ReportLab (PDF), OpenPyXL (Excel)
- **Security:** Code Obfuscation, Anti-Tampering Mechanism

---

## 🗓 Roadmap

### ✅ v2.2.0 (Current - Professional)
- [x] **Core:** Npcap 제거 및 Native Socket 엔진 탑재 (BSOD 방지)
- [x] **Stability:** Fail-Safe 로직 및 멀티스레드 자원 관리 최적화
- [x] **UX:** PySide6 기반 UI 리마스터 및 원클릭 진단 프로세스 구축
- [x] **Reporting:** 리포트 생성 속도 개선 및 포맷 고도화

### 🔮 v3.0 (Future - Enterprise)
- [ ] **AI Analysis:** LLM 기반 취약점 상세 분석 및 조치 가이드 자동 생성
- [ ] **SaaS Migration:** 클라우드 기반 통합 관제 대시보드 연동
- [ ] **Agent Mode:** 상시 모니터링을 위한 경량 에이전트 서비스 지원
- [ ] **API Support:** 타 보안 솔루션 연동을 위한 RESTful API 제공

---

## 📜 License

**Proprietary License**

Copyright © 2026 **Z-VulnScan Team**. All Rights Reserved.

본 소프트웨어는 **상용/비공개 소프트웨어**입니다. 저작권자의 사전 서면 허가 없이 본 소프트웨어의 전부 또는 일부를 무단으로 복제, 배포, 수정, 역공학(Reverse Engineering)하는 행위는 엄격히 금지됩니다.