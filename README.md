# Z-VulnScan Professional Edition v2.1  
### Network Asset Discovery & Security Visibility Tool

**Z-VulnScan Professional**은  
인가된 네트워크 환경에서 **자산 가시화, 포트 노출 현황 파악, 서비스 배너 수집**을 통해  
보안 담당자가 **사전 위험 요소를 식별하고 점검 결과를 문서화**할 수 있도록 지원하는  
**보안 가시화(Security Visibility) 및 사전 점검 도구**입니다.

본 도구는 **침투 테스트(PT) 또는 공격 도구가 아니며**,  
보안 정책 수립, 교육, 내부 점검, 감사 대응을 위한 **보조 수단**으로 설계되었습니다.

---

## 🔐 Legal & Ethical Notice (중요)

⚠ **본 프로그램은 반드시 인가된 자산 및 네트워크 환경에서만 사용해야 합니다.**

- 본 도구는 **네트워크 포트 스캔, 서비스 정보 수집 기능**을 포함합니다.
- 사전 허가 없이 제3자의 네트워크 또는 시스템을 스캔하는 행위는  
  관련 법률에 의해 **형사·민사 책임**이 발생할 수 있습니다.
- 사용자는 본 도구 사용에 따른 **모든 법적 책임을 스스로 부담**합니다.

👉 프로그램 실행 시, 위 사항에 대한 **명시적 동의(Disclaimer Dialog)**를 요구합니다.

---

## 🎯 Intended Use (권장 사용 목적)

Z-VulnScan Professional은 다음 목적에 적합합니다.

- ✅ 내부 네트워크 **자산 식별 및 현황 파악**
- ✅ 서버/서비스 **노출 포트 점검**
- ✅ 보안 감사 전 **사전 점검(Checklist 보조)**
- ✅ 보안 교육 및 실습 환경
- ✅ 점검 결과 **보고서(PDF/Excel) 자동화**

❌ 다음 용도로는 설계되지 않았습니다.

- 침투 테스트(Exploit 기반 공격)
- 무차별 외부 네트워크 스캔
- 실시간 공격 시뮬레이션

---

## 🚀 Key Features

## 📸 Screenshots
| Dashboard | Report Preview |
|---|---|
| ![Main GUI](img/dashboard.png) | ![PDF Report](img/report.png) |

### 1. Network Asset Discovery
- ICMP Ping 기반 활성 호스트 탐지
- ARP Scan을 통한 내부 네트워크 자산 식별
- 인가된 로컬 네트워크 환경 최적화

---

### 2. Port Exposure Scanning
- **Fast Scan:** 주요 포트 빠른 점검
- **Custom Scan:** 사용자 정의 포트 범위
- **Full Scan:** 전체 포트 노출 현황 분석
- TCP Connect / TCP SYN Scan 모드 제공  
  *관리자 권한 필요*

---

### 3. Service Banner Collection
- 서비스 배너 정보 수집
- 소프트웨어 버전 및 서비스 식별
- **CVE 직접 탐지 ❌**
- **참고용 보안 정보 매핑(Reference Only)**

> ⚠ 배너 기반 정보는 정확하지 않을 수 있으며,  
> 실제 취약 여부 판단은 별도의 검증이 필요합니다.

---

### 4. Professional Reporting
- **Excel Report (.xlsx)**
  - 자산 목록 / 포트 현황 / 상세 결과
  - 취약 가능 항목 시각적 강조
- **PDF Report (.pdf)**
  - 점검 개요
  - 네트워크 노출 요약
  - 감사 및 보고용 문서 활용 가능

---

### 5. Modern GUI
- PyQt5 기반 다크 모드 UI
- 실시간 진행률, ETA 표시
- 입력값 검증 및 UI 상태 제어
- 로그 콘솔 제공

---

## 🛠 Technology Stack

- **Language:** Python 3.13+
- **GUI:** PyQt5
- **Network:** Scapy, Python Socket
- **Reporting:** ReportLab, OpenPyXL
- **Build & Security:** PyArmor, PyInstaller

---

## 📦 Deployment

- **Standalone Executable (EXE)**
- 별도 Python 환경 불필요
- 단일 파일 실행
- 내부 배포 및 폐쇄망 환경 지원

---

## 🧭 Product Positioning

Z-VulnScan Professional은 다음 범주에 속합니다.

| 구분 | 해당 여부 |
|---|---|
| 네트워크 가시화 도구 | ⭕ |
| 보안 설정 사전 점검 | ⭕ |
| 교육/훈련용 도구 | ⭕ |
| 취약점 자동 공격 도구 | ❌ |
| 침투 테스트 프레임워크 | ❌ |

> **본 도구는 “보안 판단을 대체하지 않으며”,  
> 보안 담당자의 의사결정을 보조합니다.**

---

## 🗓 Roadmap

- [x] 자산 탐지 및 포트 스캔
- [x] GUI 기반 스캔 제어
- [x] PDF / Excel 리포트
- [ ] 실행 전 법적 동의 팝업
- [ ] OS별 스캔 모드 분리 (Windows/Linux)
- [ ] CVE 연관 정보 *Reference View* 제공
- [ ] 정책 기반 스캔 프로파일

---

## ✅ Supported Audit List (KISA)

- 🐧 Linux Server (Unix 계열)

|  코드 | 항목명              | 주요 점검 내용                        |
|--------|---------------------|---------------------------------------|
| U-01 | root 원격 접속 제한 | sshd_config PermitRootLogin 설정 점검 |
| U-02 | 패스워드 복잡성     | pwquality.conf 설정 점검              |
| U-03 | 계정 잠금 임계값    | pam_tally2/faillock 설정 점검         |
|  ...  | ...                 | ...                                   |
|  U-64 | 로그온 시 경고 메시지      | OS 버전 등 불필요한 정보 노출 점검     |

- 🪟 Windows Server (New!)

| 코드 | 항목명             | 주요 점검 내용                                |
|------|--------------------|-----------------------------------------------|
| W-01 | Administrator 계정 | 이름기본 관리자 계정 이름 변경 및 활성화 여부 |
| W-02 | Guest 계정 상태    | Guest 계정 비활성화 여부 점검                 |
| W-03 | 불필요한 서비스    | Telnet, FTP 등 취약한 서비스 실행 여부        |
|  ...  | ...                 | ...                                   |
|  w-70 | 자동 로그인 기능     | 자동 로그인 시 활성화 여부    |

---

> ℹ **참고:** 위 KISA 진단 항목(Compliance)은 대상 자산에 대한 **SSH/WinRM 인증 정보(ID/PW)**가 제공된 경우에만 정밀 진단이 가능합니다. 비인증 시 포트 및 배너 정보만 제공됩니다.

---
## 🔮 Future Roadmap (Enterprise)
- v3.0: Centralized Management (MySQL/MariaDB 연동 지원).
- Web Dashboard: Java(JSP) 기반의 웹 관제 콘솔 제공 (Optional).
- CVE Scan: NVD 데이터베이스 연동을 통한 버전 기반 취약점(CVE) 스캔.

## 📜 License

**Proprietary License**

Copyright © 2025  
Z-VulnScan Team. All Rights Reserved.

본 소프트웨어는 사전 허가 없이 재배포, 역공학, 무단 수정할 수 없습니다.
