# build_final_v3.ps1
#
# CI(.github/workflows/release.yml)와 로컬 수동 하이브리드 빌드가 공유하는 단일
# 소스. 예전에는 Z-VulnScan_Build_Work/ 안에만 있었고 .gitignore 대상이라 버전
# 관리가 안 됐다 - CI가 쓰려면 추적 대상 경로가 필요해서 이곳으로 옮겼다.
#
# 원본과의 차이는 딱 하나: $VERSION이 하드코딩("v3.0.0")이 아니라 -Version
# 파라미터로 받는다(기본값은 기존 하드코딩 값과 동일해서 로컬 수동 실행은 예전과
# 똑같이 동작). $DIST_DIR도 예전엔 "Z-VulnScan_Professional_v3.0.0_Final"로
# 따로 하드코딩돼 있어서 $VERSION을 바꿔도 폴더명이 안 바뀌는 버그가 있었는데,
# 이번에 $VERSION에서 파생되도록 고쳤다.
param(
    [string]$Version = "v3.0.0"
)

# 에러 발생 시 즉시 중단
$ErrorActionPreference = "Stop"

# 버전 정보
$VERSION = $Version
$APP_NAME = "Z-VulnScan_Professional_Edition_$VERSION"
$DIST_DIR = "Z-VulnScan_Professional_${VERSION}_Final"

# 난독화된 소스가 있는 위치
$SRC_DIR = "dist\obfuscated"

# rules/*_rules.json을 암호화해서 담아둘 스테이징 폴더 (평문 rules/*.json
# 자체는 여기 안 들어가고 .enc로만 들어간다 - 아래 [4/4] PyInstaller 단계가
# rules/ 대신 이 폴더를 배포판의 "rules"로 채택한다)
$RULES_STAGED_DIR = "dist\rules_staged"

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host " 🚀 Hybrid Build Started: $APP_NAME" -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------
# [1/4] rules/*_rules.json 암호화 스테이징
# ---------------------------------------------------------------------
Write-Host "[1/4] Encrypting rules/*_rules.json..." -ForegroundColor Yellow
python ci\encrypt_rules.py rules $RULES_STAGED_DIR
if ($LASTEXITCODE -ne 0) {
    Write-Host "`n ❌ Rules encryption failed!" -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------
# [2/4] 누락된 모듈(Cython + GUI) 수동 병합
# ---------------------------------------------------------------------
Write-Host "[2/4] Merging modules into obfuscated folder..." -ForegroundColor Yellow

$modules_to_copy = @("core", "utils", "output", "gui")

foreach ($folder in $modules_to_copy) {
    $dest_path = "$SRC_DIR\scanner_engine\$folder"
    if (-not (Test-Path $dest_path)) {
        New-Item -ItemType Directory -Force -Path $dest_path | Out-Null
    }

    $source_path = "scanner_engine\$folder"

    if ($folder -eq "gui") {
        # GUI: .py 스크립트 복사
        if ((Get-ChildItem $dest_path).Count -eq 0) {
            Copy-Item "$source_path\*.py" -Destination $dest_path -Force
            Write-Host "   -> Copied GUI scripts (.py) to: $folder" -ForegroundColor Gray
        }

        # [대시보드 웹뷰, 2026-09] gui/web/(dashboard.html/js + vendor/chart.umd.min.js)는
        # .py가 아니라서 PyArmor도 위 *.py 복사도 건드리지 않는다 - 안 하면 배포판에서
        # 대시보드 화면이 빈 페이지로 뜬다. 매번 최신 상태로 덮어써서 스테일 웹 자산이
        # 남지 않게 한다.
        $webSrc = "$source_path\web"
        if (Test-Path $webSrc) {
            $webDest = "$dest_path\web"
            if (Test-Path $webDest) { Remove-Item -Recurse -Force $webDest }
            Copy-Item $webSrc $webDest -Recurse -Force
            Write-Host "   -> Copied dashboard web assets (html/js/vendor) to: gui/web" -ForegroundColor Gray
        }
    }
    else {
        # Core/Utils/Output: .pyd 모듈 복사
        # [주의] discovery.py도 pyd로 변환되어 있어야 복사됨!
        if (Test-Path $source_path) {
            Copy-Item "$source_path\*.pyd" -Destination $dest_path -Force
            Write-Host "   -> Copied Cython modules (.pyd) for: $folder" -ForegroundColor Gray
        }
    }
}

# ---------------------------------------------------------------------
# [3/4] PyArmor 런타임 폴더 자동 감지
# ---------------------------------------------------------------------
$RUNTIME_DIR = Get-ChildItem "$SRC_DIR" -Directory -Filter "pyarmor_runtime_*" | Select-Object -ExpandProperty Name -First 1

if (-not $RUNTIME_DIR) {
    Write-Error "❌ PyArmor 런타임 폴더를 찾을 수 없습니다! 2단계(pyarmor gen)를 확인하세요."
    exit
}
Write-Host "[3/4] Found Runtime: $RUNTIME_DIR" -ForegroundColor Gray

# 기존 빌드 정리
if (Test-Path $DIST_DIR) { Remove-Item -Recurse -Force $DIST_DIR }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
if (Test-Path "*.spec") { Remove-Item -Force "*.spec" }

# ---------------------------------------------------------------------
# [4/4] PyInstaller 실행
# ---------------------------------------------------------------------
# [2026-09 "exe 부팅 속도" 피드백] 처음엔 onedir(압축 해제 자체를 없앰)로
# 전환했었는데, 사용자가 배포 형태는 onefile 그대로 유지하고 싶어해서
# (installer/zip 없이 exe 한 개로 배포하는 편의성 우선) onefile로 되돌리고,
# 대신 --splash로 압축 해제~엔진 초기화 동안 "실행 중"임을 보여주는 안내 화면을
# 띄우는 쪽으로 방향을 바꿨다. 여기서 한 걸음 더 - "진행바가 실제로 작동하게"
# 해달라는 요청까지 반영하려면 Splash(text_pos=...)로 텍스트를 실시간 갱신해야
# 하는데, 그 옵션은 PyInstaller CLI(--splash)에는 없고 .spec 파일에서만 쓸 수
# 있다. 그래서 순수 CLI 인자 나열 대신 ci/zvulnscan.spec(기존 CLI 인자를 전부
# 그대로 옮겨 담음)을 쓰도록 바꿨다 - main.py가 실제 부팅 단계(무거운 import,
# DB 복호화, 메인 창 표시)마다 pyi_splash.update_text()로 진행바 문구를 갱신한다.
# 스플래시 이미지(assets/splash.png)는 Z-VulnScan_Build_Work/splash_Image.psd
# 원본 디자인을 바탕으로 다시 그린 것을 정적 에셋으로 커밋해 둔 것을 쓴다.
Write-Host "`n[4/4] Packaging (onefile + live-progress splash screen)..." -ForegroundColor Yellow

# .spec은 버전마다 달라지는 EXE 이름과 PyArmor 런타임 폴더명을 하드코딩할 수 없어서
# 환경변수로 넘긴다 (ci/zvulnscan.spec 상단 주석 참고).
$env:ZVULN_APP_NAME = $APP_NAME
$env:ZVULN_RUNTIME_DIR = $RUNTIME_DIR

pyinstaller --noconfirm --clean --distpath $DIST_DIR ci/zvulnscan.spec

# 4. 결과 확인
if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=======================================================" -ForegroundColor Green
    Write-Host " 🎉 BUILD SUCCESS! (Hybrid Obfuscation Complete)" -ForegroundColor Green
    Write-Host " 📂 Output: $DIST_DIR\$APP_NAME.exe" -ForegroundColor White
    Write-Host "=======================================================" -ForegroundColor Green

    if ($env:CI -ne "true") {
        Invoke-Item $DIST_DIR
    }
}
else {
    Write-Host "`n ❌ Build Failed!" -ForegroundColor Red
    exit 1
}
