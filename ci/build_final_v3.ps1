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

# 오픈소스 라이선스 고지 목록(설정 > 오픈소스 라이선스에 표시)을 gui/web/에 생성한다 - 아래 웹 자산 복사보다 먼저 실행해야 포함된다
python ci\gen_third_party_notices.py
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

# [웹 대시보드 모드, 2026-09] scanner_engine/ 루트의 web_dashboard_server는 위 네 폴더(core/utils/output/gui)
# 어디에도 속하지 않아 병합 단계에서 빠져 있었다 - 그대로 두면 exe에서 웹 모드를 골랐을 때
# `from web_dashboard_server import ...`가 ModuleNotFoundError로 죽는다. 스캔 실행/로그인/세션/리포트 로직이라
# 다른 엔진 모듈처럼 Cython으로 컴파일한 .pyd(ci/build_cython.py)를 main.py 옆에 복사한다.
# (UI 파일인 gui/main_window.py 등은 PyArmor 트라이얼 한계로 평문이며, UI라 유출 영향이 작다고 판단해 그대로 둔다.)
$wdsPyd = Get-ChildItem "scanner_engine" -Filter "web_dashboard_server*.pyd" | Select-Object -First 1
if ($wdsPyd) {
    Copy-Item $wdsPyd.FullName -Destination "$SRC_DIR\scanner_engine" -Force
    Write-Host "   -> Copied compiled web_dashboard_server (.pyd) next to main.py" -ForegroundColor Gray
}
elseif ($env:CI -eq "true") {
    Write-Error "web_dashboard_server .pyd가 없습니다 - Cython 컴파일 단계를 확인하세요 (평문 소스로 배포하지 않기 위해 CI에서는 중단)"
    exit 1
}
else {
    Copy-Item "scanner_engine\web_dashboard_server.py" -Destination "$SRC_DIR\scanner_engine" -Force
    Write-Host "   -> [경고] .pyd가 없어 평문 web_dashboard_server.py를 복사했습니다 (로컬 빌드 전용)" -ForegroundColor Yellow
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
# [2026-09-20 배포 형태: onedir] PySide6/paramiko/psycopg2/pymssql이 LGPL이라 사용자가 그 라이브러리를
# 수정본으로 교체할 수 있어야 한다 - onefile은 exe 안에 묶여 교체가 어려워 onedir로 바꿨다
# (라이브러리가 _internal 폴더에 낱개 파일로 남는다. ci/zvulnscan.spec 상단 주석 참고).
# 이전(2026-09-02)에는 "exe 하나로 배포"하는 편의 때문에 onefile을 썼고, 압축 해제 대기 시간은 --splash로
# 가렸다. onedir은 압축 해제 자체가 없어 부팅도 빠르지만, 스플래시(assets/splash.png)와 main.py의
# pyi_splash 진행바 문구는 그대로 쓴다. 배포는 결과 폴더를 zip으로 묶어서 한다.
# 스플래시 진행바 텍스트는 Splash(text_pos=...)로만 갱신할 수 있어 CLI 대신 .spec을 쓴다.
Write-Host "`n[4/4] Packaging (onedir + live-progress splash screen)..." -ForegroundColor Yellow

# .spec은 버전마다 달라지는 EXE 이름과 PyArmor 런타임 폴더명을 하드코딩할 수 없어서
# 환경변수로 넘긴다 (ci/zvulnscan.spec 상단 주석 참고).
$env:ZVULN_APP_NAME = $APP_NAME
$env:ZVULN_RUNTIME_DIR = $RUNTIME_DIR

pyinstaller --noconfirm --clean --distpath $DIST_DIR ci/zvulnscan.spec

# 4. 결과 확인
if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=======================================================" -ForegroundColor Green
    Write-Host " 🎉 BUILD SUCCESS! (Hybrid Obfuscation Complete)" -ForegroundColor Green
    # LGPL 고지 파일을 배포 폴더 루트에 함께 넣고, 폴더째 zip으로 묶는다(배포 단위)
    Copy-Item "ci\LGPL_NOTICE.txt" -Destination "$DIST_DIR\$APP_NAME\LGPL_NOTICE.txt" -Force
    $zipPath = "$DIST_DIR\$APP_NAME.zip"
    if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
    Compress-Archive -Path "$DIST_DIR\$APP_NAME" -DestinationPath $zipPath -CompressionLevel Optimal
    Write-Host " 📂 Output: $DIST_DIR\$APP_NAME\$APP_NAME.exe (folder) / $zipPath" -ForegroundColor White
    Write-Host "=======================================================" -ForegroundColor Green

    if ($env:CI -ne "true") {
        Invoke-Item $DIST_DIR
    }
}
else {
    Write-Host "`n ❌ Build Failed!" -ForegroundColor Red
    exit 1
}
