# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[버전 업데이트 배포 경로] 지금은 이 프로그램을 배포할 실제 호스팅(공식 홈페이지,
사내 서버 등)이 없어서 "어디서 새 버전을 확인해야 하는지" 자체가 정해져 있지
않다. 그렇다고 존재하지 않는 주소를 미리 박아두면 나중에 실제로 그 주소를
못 쓰게 되거나, 지금 당장 아무 데도 없는 곳에 조용히 네트워크 요청을 보내는
찜찜한 코드가 남는다.

그래서 이 모듈은 AppConfig.UPDATE_CHECK_URL이 실제로 채워지기 전까지는 항상
아무 요청도 보내지 않고 None만 반환한다(완전히 비활성 상태). 나중에 실제
배포 경로(예: 자체 홈페이지의 version.json)가 정해지면 그 값만 채우면
이 함수가 그대로 동작한다 - 이번 세션의 라이선스 강제적용 스위치와 같은
"개발은 해두되 기본은 꺼둔다" 패턴을 그대로 따른다.
"""
import requests
from core.config import AppConfig
from utils.logger import AppLogger


def check_for_updates(timeout=3):
    """
    기대하는 원격 응답 형식(JSON): {"latest_version": "v3.1", "download_url": "...", "notes": "..."}
    반환: 새 버전이 있으면 그 dict, 없거나(최신 상태) URL 미설정/조회 실패면 None.
    """
    url = getattr(AppConfig, "UPDATE_CHECK_URL", "")
    if not url:
        return None

    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        AppLogger.log_error("[UpdateChecker] Failed to check for updates", e)
        return None

    latest = data.get("latest_version")
    if latest and latest != AppConfig.VERSION:
        return data
    return None
