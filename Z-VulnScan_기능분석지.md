# Z-VulnScan Professional Edition — 기능 분석지

- **문서 목적:** 기능별 성숙도·비즈니스 가치·리스크를 분석해 개발/투자 우선순위 판단 근거를 제공. 항목별 상세 스펙은 `기술 명세서.md`가 단일 소스이며, 이 문서는 그 위에 **분석(해석)**을 더한다 — 내용이 어긋나면 `기술 명세서.md`가 우선한다.
- **범위:** Z-VulnScan Professional Edition 전체 제품.
- **작성 기준일:** 2026-08-05
- **성숙도 등급:** A(실전 검증됨) / B(구현 완료, 실측·전수검증 대기) / C(부분 구현, 한계 명확) / D(코드 존재, 비활성) / E(로드맵, 미착수)

---

## 1. 모듈별 성숙도 분석

| 모듈 | 핵심 기능 | 성숙도 | 분석 |
|---|---|:---:|---|
| Discovery 엔진 (`advanced_scanner.py`) | 생존확인/포트스캔/배너/OUI/UDP | A | 5건의 실측 버그가 이번 정밀검수에서 발견·수정됨(소켓 미초기화, 에러코드 하드코딩 등) — 검증 이력이 있어 신뢰도 높음. hostname 역DNS는 OT망에서 구조적 한계(§4 참고) |
| Audit 엔진 — SSH/WinRM (`ssh_inspector.py`/`windows_inspector.py`) | U-xx/W-xx/PC-xx 판정 | A | Linux 67 + Windows 64 + PC 18 = 149개 항목 라이브. **2026-08-05 `vulnerable_keyword`/`safe_keyword` 룰 117개 전수 재검토 완료** — Linux는 root 전용 파일(`/etc/shadow` 등) 접근 + `privileged` 미설정 패턴을 전 룰셋 스크립트로 교차검증(U-13만 해당, 수정 완료; U-18/U-63/U-33/WEB-07은 검토 후 실제 리스크 아님으로 판정 - 각각 `stat`만 사용/`vulnerable_keyword` 자체가 없는 MANUAL 전용 룰/world-readable 웹 docroot). Windows는 SAM/보안 하이브 등 민감 패턴 스캔 결과 0건, WinRM 관리자 계정 관행상 잔여 리스크 낮음으로 판단 |
| Audit 엔진 — DB (`database_inspector.py`) | MySQL/PostgreSQL/MSSQL/Oracle | B (MySQL/PG는 A) | MySQL·PostgreSQL은 실전 검증됨(34개). MSSQL·Oracle은 2026-08-05 배선 완료(각 21/22개, `python-oracledb` thin 모드 사용)했으나 실서버 미검증 - Oracle은 서비스명 입력 UI가 없어 기본값(`ORCL`)으로만 시도(§3 기술부채). `vulnerable_keyword` 위험 클래스는 `execute_query()`가 예외 시 `None`을 반환해 `judge_rule()`이 MANUAL로 우선 처리하므로 구조적으로 보호됨 |
| 판정 엔진 (`utils/rule_judge.py`) | 6단계 판정 로직 | A | 엔진 자체는 완전히 룰/엔진 무관 범용 설계 — 유지보수성 우수. 권한부족 감지(`PERMISSION_DENIED_SIGNALS`)가 이미 잘 설계돼 있으나 룰의 stderr 처리 방식에 따라 무력화될 수 있음(U-13 사례) |
| 교차검증(Cross-check) (`crosscheck_engine.py`) | 외부 TXT 재판정 | A | DB 미접근 설계로 라이브 스캔과 완전 분리 — 감사 안전성 우수 |
| PC 로컬 스크립트 (`pc_toolkit.py`) | WinRM 불가 PC 대상 로컬 진단 | D | 코드는 완성됐으나 UI 진입점 비활성. OT 에이전트 킷 로드맵의 기반 자산으로 재활용 가치 있음(단, 파일반입 통제 문제는 별도) |
| 수동 진단 입력 (`manual_audit_dialog.py`) | 육안 점검 결과 직접 입력 | A | 통제 수준 무관하게 항상 동작하는 유일한 계층. TXT 증적에 자동진단용 명령어가 그대로 찍혀 오해를 부르던 문제(`operator="수동입력"` 건은 "(CMD) 명령어" 대신 "육안 점검으로 인한 별첨 증적 처리" 문구로 대체)를 2026-08-05 해결함(`text_report.py`) |
| **룰셋 증분 업데이트 (`utils/rule_update.py`, `ci/sign_rules_update.py`)** | Ed25519 서명 기반 룰셋 OTA | B | 서명/검증 왕복 테스트 통과, Settings 옵트인 UI 연결 완료. 실제 GitHub Release 배포·현장 검증은 아직. 공개키는 `config/rule_update_config.json`으로 외부화(GS 인증 대비 하드코딩 배제) |
| **UI/UX "신뢰할 수 있는 작업대"** | 디자인 리스킨 + 탭 역할 분리 | A | `dashboard_widgets.py` COLORS/`styles.py` 전역 QSS 양쪽에 반영, 라이트+다크 모두 적용(다크는 이번에 신규 설계). 대시보드=현황판 전용, 진단결과/Waiver/Expert/수동입력=자산 탭으로 이동 완료 |
| 리포트 (Excel/PDF/TXT) | 3종 출력 + Diff 리포트 | A | hostname 실제값 반영, 등급별 차등 노출까지 구현됨. TXT는 고객사 매크로 호환 포맷 유지가 제약조건 |
| 보안 강화 (SSH TOFU, WinRM HTTPS 우선, 크리덴셜 저장) | 접속 보안 | A | 실전 수준. Command Injection 방지(`is_safe_host`)까지 갖춤 |
| 데이터 보호 (DB Fernet 암호화, 룰셋 암호화) | at-rest 보호 | A | 2026-07-30 룰셋 암호화 신설 — 핵심 IP(KISA 판정 로직) 평문 노출 문제를 뒤늦게 발견해 해결한 사례. PyArmor 신뢰 모델에 기대는 수준이라 완벽한 DRM은 아님을 인지하고 있어야 함 |
| 라이선스 시스템 | 3등급, 위변조 방지 | B | 키 취소가 로컬 목록 기반(실시간 원격 회수 아님) — 상용화 확대 시 재검토 필요 |
| hostname 3단 폴백(역DNS/실측/엑셀매핑) + 커버리지 추적 | OT망 자산 식별 + 감사 완결성 | A | `표준제안서.md` §4 참고. 2026-08-05 구현·테스트 완료(엑셀 hostname 매핑+diff, DB 미해결자산 조회, 대시보드 경고, Excel 리포트 반영). 로컬 스크립트 킷(4단)은 여전히 로드맵 |

## 2. 라이선스 등급별 기능 매트릭스 (기 구현)

| 기능 | Standard | Professional | Enterprise |
|---|:---:|:---:|:---:|
| PDF 리포트 | ✅ | ✅ | ✅ |
| Excel 리포트 | — | ✅ | ✅ |
| 증적 노출 범위 | 제한 | 확대 | 전체 |
| 조치방안 노출 범위 | 제한 | 확대 | 전체 |
| 전문가 모드(룰 범위 사전 배제) | — | — | ✅ |

*(키 미등록 시 기본값은 Enterprise로 동작 — 스위치가 아닌 설계상 기본값이므로 상용 배포 전 반드시 재확인 필요)*

## 3. 기술부채 목록 (우선순위순)

| 순위 | 항목 | 유형 | 영향 |
|---|---|---|---|
| 1 | DB 룰셋의 "쿼리는 성공하지만 뷰 제약으로 조용히 0건" 잔여 리스크 | 신뢰성(낮은 확신도) | 실 DB 테스트베드 없이는 검증 불가 - `execute_query()` 예외 시엔 이미 MANUAL로 안전하게 처리되므로(§1 참고), 예외 없이 빈 결과가 나오는 극히 좁은 케이스만 해당 |
| 2 | Oracle 서비스명(Service Name) 입력 UI 부재 | 기능 공백 | 커넥션 자체는 배선됐으나 host+port만으로 접속 안 됨, 기본값(`ORCL`)으로만 시도 중 |
| 3 | `web_dashboard/` 빈 스캐폴드 | 정리 대상 | 용도 불명, 미착수 사이드 프로젝트로 추정 |

*(~~포트 스캔 포트 단위 병렬성 부재~~, ~~죽은 코드 정리~~, ~~`library.py` PyQt5 표기~~, ~~Oracle DB 커넥션 미배선~~, ~~`vulnerable_keyword` 단일조건 룰 전수 재검토~~, ~~`TBL_ASSETS.memo`→`description` 리네임~~, ~~수동 진단 입력 TXT 증적 표기 개선~~은 2026-08-05 완료돼 이 목록에서 제외됨 — §1 표 참고)*

## 4. 시장 포지셔닝 요약

상세는 `표준제안서.md` §5 참고. 요지: 대기업 세그먼트는 가격이 아닌 확실성으로, 중소 세그먼트는 유일한 대안으로 어필 — 동일 기능(hostname 4단 폴백 + 커버리지 추적)이 서로 다른 이유로 두 세그먼트 모두에 통하는 구조.
