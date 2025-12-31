import subprocess
import sys
import pkg_resources

# 설치할 라이브러리 목록 (Z-VulnScan Enterprise 의존성)
required_packages = [
    "PyQt5",        # GUI 프레임워크
    "scapy",        # 네트워크 패킷 스캔
    "paramiko",     # SSH 연결 (Linux)
    "pywinrm",      # WinRM 연결 (Windows)
    "openpyxl",     # 엑셀 리포트 생성
    "reportlab",    # PDF 리포트 생성
    "keyring",      # [New] 자격증명 보안 저장소
    "pyinstaller"   # EXE 실행 파일 빌드 도구
]

def install(package):
    """pip를 사용하여 패키지를 설치합니다."""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"[Success] '{package}' installed successfully.")
    except subprocess.CalledProcessError:
        print(f"[Error] Failed to install '{package}'.")

def check_and_install():
    print("=" * 50)
    print("🚀 Z-VulnScan Enterprise 환경 설정 시작")
    print("=" * 50)

    # 1. pip 업그레이드
    print("[*] Upgrading pip...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    except Exception:
        print("[Warning] Could not upgrade pip. Continuing...")

    installed_packages = {pkg.key for pkg in pkg_resources.working_set}
    
    # 2. 패키지 설치 루프
    for package in required_packages:
        package_name = package.lower()
        if package_name in installed_packages:
            print(f"[Skip] '{package}' is already installed.")
        else:
            print(f"[*] Installing {package}...")
            install(package)

    print("=" * 50)
    print("✅ 모든 라이브러리 설치가 완료되었습니다!")
    print("   이제 'main_gui.py'를 실행하거나 빌드할 수 있습니다.")
    print("=" * 50)

if __name__ == "__main__":
    check_and_install()
    input("\nPress Enter to exit...") # 실행 후 창이 바로 꺼지는 것 방지