# Z-VulnScan Professional Edition — 프로젝트 지침

## 세션 시작 시 필수 확인

이 저장소에서 작업을 시작할 때는 저장소 루트의 **`PROJECT_MANIFEST.md`**를 먼저 읽는다.

- 이 파일은 `.gitignore`에 등록돼 있어 Git에는 없다 — 로컬 디스크에만 존재하므로 fresh clone에는 없을 수 있다. 없으면 사용자에게 존재 여부를 확인한다.
- 전체 디렉터리 구조, `scanner_engine/` 아키텍처(모듈별 역할), DB 스키마, `rules/` 룰셋 구성, git-ignore된 파일 전체 목록과 각각의 용도(민감정보 포함 여부까지), 라이선스 등급 시스템, 빌드 프로세스, 실제 테스트 VM 3대 정보, KISA 대조검증용 참고 스크립트(`00. Script/`) 목록, 알려진 이슈, 세션 이력 요약이 들어있다.
- **오래됐을 수 있다** — 코드를 직접 고친 뒤에는 매니페스트 내용이 실제 코드와 어긋날 수 있으므로, 매니페스트의 서술을 그대로 믿지 말고 코드/파일로 재확인한 뒤 사용한다.
- 이 저장소에서 의미 있는 변경(새 기능, 구조 변경, git-ignore 대상 추가/삭제, 새로운 민감 파일 발생 등)을 했다면, 세션 끝에 `PROJECT_MANIFEST.md`도 함께 갱신할지 사용자에게 확인한다.

## 함께 참고할 문서

- `ROADMAP.md` (Git-ignore) — 실제 일정/고객사 맥락이 담긴 작업 계획서. 존재하면 진행 중인 작업의 배경으로 참고.
- `README.md` (Git 추적) — 공개용 프로젝트 설명. 기능 변경 시 함께 최신화 대상.

## 민감정보 취급 원칙

`PROJECT_MANIFEST.md`의 ⚠ 표시 항목(`.env`, `zvuln_scan.db*`, `DB_RECOVERY_KEY_BACKUP.txt`, `license.dat`, `licenses_generated.txt`, `issued_licenses.json`, `ROADMAP.md`, `00. Script/` 등)의 **실제 값(비밀번호·키·고객사 세부정보)은 어떤 문서에도 복사하지 않는다.** 존재 여부와 용도만 기록한다.
