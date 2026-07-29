# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[버전 업데이트 배포 경로] GitHub Releases(rorena15/Z-V_Scan, public 저장소)를 사용한다.
AppConfig.UPDATE_CHECK_URL이 GitHub REST API의 "최신 릴리즈" 엔드포인트를 가리키면
이 모듈이 그 응답(tag_name/assets/body)을 파싱해 현재 버전보다 새 릴리즈가 있는지
판단한다. URL이 비어있으면(과거처럼) 완전히 비활성 상태로 즉시 None을 반환한다.

GitHub API 호출 시 User-Agent 헤더가 없으면 403이 나므로 반드시 포함한다.
아직 릴리즈가 하나도 없는 저장소는 404를 반환하는데, 이는 에러가 아니라 정상
상태이므로 로그에 에러로 남기지 않고 조용히 None을 반환한다.
"""
import requests
from core.config import AppConfig
from utils.logger import AppLogger

_MAX_NOTES_LEN = 500


def _parse_version(v):
    """"v3.0.0" 같은 문자열을 (3, 0, 0) 튜플로 정규화한다. 접두 v/V, 비숫자 접미사(-beta 등)는 무시."""
    v = (v or "").strip()
    if v[:1].lower() == "v":
        v = v[1:]
    nums = []
    for part in v.split("."):
        digits = ""
        for ch in part:
            if ch.isdigit():
                digits += ch
            else:
                break
        nums.append(int(digits) if digits else 0)
    return tuple(nums) if nums else (0,)


def _is_newer(remote_version, local_version):
    r = _parse_version(remote_version)
    l = _parse_version(local_version)
    length = max(len(r), len(l))
    r = r + (0,) * (length - len(r))
    l = l + (0,) * (length - len(l))
    return r > l


def check_for_updates(timeout=5):
    """
    반환: 더 최신 릴리즈가 있으면 {"latest_version", "notes", "download_url"} dict,
    없거나(최신 상태) URL 미설정/릴리즈 없음/조회 실패면 None.
    """
    url = getattr(AppConfig, "UPDATE_CHECK_URL", "")
    if not url:
        return None

    try:
        resp = requests.get(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"Z-VulnScan-UpdateChecker/{AppConfig.VERSION}",
            },
            timeout=timeout,
        )
        if resp.status_code == 404:
            # 아직 발행된 릴리즈가 없는 정상 상태 - 에러로 취급하지 않는다.
            return None
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        AppLogger.log_error("[UpdateChecker] Failed to check for updates", e)
        return None

    tag = data.get("tag_name") or ""
    if not tag or not _is_newer(tag, AppConfig.VERSION):
        return None

    assets = data.get("assets") or []
    download_url = assets[0].get("browser_download_url") if assets else None
    if not download_url:
        download_url = data.get("html_url", url)

    notes = (data.get("body") or "").strip()
    if len(notes) > _MAX_NOTES_LEN:
        notes = notes[:_MAX_NOTES_LEN].rstrip() + "..."

    return {
        "latest_version": tag,
        "notes": notes,
        "download_url": download_url,
    }
