import subprocess
import sys
import os

# [정정] 예전엔 여기 자체적으로 PyQt5/scapy 등 실제 코드와 어긋난 하드코딩 목록을
# 들고 있었다 - requirements.txt가 이미 단일 소스로 정리돼 있는데 이 파일이 별도로
# 목록을 또 유지하면서 둘이 다시 어긋나는 문제가 재발할 뿐이라, 여기서는 목록을
# 중복 관리하지 않고 requirements.txt를 그대로 설치한다.
_REQUIREMENTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")


def check_and_install():
    print("=" * 50)
    print("Z-VulnScan Enterprise 환경 설정 시작")
    print("=" * 50)

    print("[*] Upgrading pip...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    except Exception:
        print("[Warning] Could not upgrade pip. Continuing...")

    print(f"[*] Installing from {_REQUIREMENTS_PATH} ...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", _REQUIREMENTS_PATH])
    except subprocess.CalledProcessError:
        print("[Error] requirements.txt 설치 중 일부 패키지가 실패했습니다. 위 로그를 확인하세요.")
        return

    print("=" * 50)
    print("모든 라이브러리 설치가 완료되었습니다!")
    print("   이제 'main_gui.py'를 실행하거나 빌드할 수 있습니다.")
    print("=" * 50)


if __name__ == "__main__":
    check_and_install()
    input("\nPress Enter to exit...")  # 실행 후 창이 바로 꺼지는 것 방지
