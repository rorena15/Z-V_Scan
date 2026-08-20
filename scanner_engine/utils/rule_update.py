# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[룰셋 증분 업데이트] GitHub Releases에 첨부된 rules_update.zip(+.sig)를 받아
Ed25519 서명 검증 후에만 exe 옆 rules/ 폴더에 반영한다.

exe 자체는 이 기능의 대상이 아니다(별도 로드맵 - onedir 전환 검토와 함께 논의).
룰의 command 필드는 SSH/WinRM으로 대상 호스트에서 실제 실행되므로(privileged:
true면 sudo까지), 서명 검증에 실패한 업데이트를 반영하는 건 진단 대상 전체에
대한 RCE 공급망 공격을 허용하는 것과 같다 - 그래서 검증 실패 시 무조건
폐기하고 파일 시스템은 절대 건드리지 않는다.

RULE_ENCRYPTION_KEY(rule_crypto.py, 대칭키)와는 목적이 다르다:
- RULE_ENCRYPTION_KEY: 룰셋 "내용"을 못 읽게 감춘다 (콘텐츠 기밀성)
- 이 모듈의 서명 검증: 이 업데이트 파일이 "진짜 개발자가 배포한 게 맞는지"
  증명한다 (배포 채널 인증) - GitHub 계정이 탈취되는 경우까지 막기 위함.
둘은 서로 대체하지 않고 각자의 역할만 한다. 개인키는 이 저장소/exe/CI 그
어디에도 없다 - 개발자 하드웨어 보안키에만 있고, ci/sign_rules_update.py로
릴리즈마다 로컬에서 수동 서명한다. 공개키/자산 파일명은 소스에 하드코딩하지
않고 config/rule_update_config.json에서 읽는다(_load_update_config 참고,
GS 인증 대비 하드코딩 배제 원칙).

기본 OFF(app_settings.ruleset_auto_update) - 사용자가 Settings에서 명시적으로
켜야만 이 모듈이 실제로 네트워크에 나간다(OT/에어갭 환경 배려, update_checker.py와
동일한 옵트인 철학).
"""
import os
import sys
import io
import json
import base64
import zipfile

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.config import AppConfig
from utils.app_settings import get_base_dir, load_settings
from utils.logger import AppLogger

_config_cache = None
_trust_anchor_cache = None


def _load_update_config():
    """[GS 인증 대비 - 하드코딩 배제] 자산(zip/sig) 파일명을 소스 상수가 아니라
    config/rule_update_config.json에서 읽는다. 이 파일명들은 보안이 걸린 값이
    아니므로(신뢰 여부는 어차피 서명 검증이 결정) exe 옆 config/ 폴더를 먼저
    찾고 없으면 내장 사본으로 폴백해도 안전하다.

    [버그 수정] 예전엔 public_key_b64(신뢰 루트)도 이 함수로 같이 읽었는데, 그러면
    exe 옆의 이 파일을 로컬에서 통째로 바꿔치기해서 검증 키 자체를 공격자 키로
    바꿔치기할 수 있었다(그러면 공격자가 자기 키로 서명한 악성 룰셋도 "검증 통과"로
    나옴). 신뢰 루트는 절대 이 경로로 읽지 않는다 - _load_trust_anchor() 참고."""
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    external_path = os.path.join(get_base_dir(), 'config', 'rule_update_config.json')
    candidates = [external_path]
    if hasattr(sys, '_MEIPASS'):
        candidates.append(os.path.join(sys._MEIPASS, 'config', 'rule_update_config.json'))

    for path in candidates:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                _config_cache = json.load(f)
            return _config_cache

    raise FileNotFoundError(
        "config/rule_update_config.json을 찾을 수 없습니다 - 룰셋 업데이트 서명 검증에 필요합니다."
    )


def _load_trust_anchor():
    """[신뢰 루트 전용 - exe 옆 경로에서는 절대 읽지 않음] public_key_b64는 반드시
    PyInstaller 번들 내부(_MEIPASS, PyArmor로 보호된 실행파일 안)에서만 읽는다.
    exe 옆 config/ 폴더는 설치 후 파일시스템 쓰기 권한만 있으면 누구나 덮어쓸 수
    있는 위치라, 신뢰 루트를 거기서 읽으면 검증 로직 자체가 무의미해진다.
    개발 환경(비frozen)에서는 번들 개념이 없으므로 저장소 내부 config/를 그대로
    쓴다 - 이 구분이 의미 있는 건 오직 실제 배포되는 frozen 빌드뿐이다."""
    global _trust_anchor_cache
    if _trust_anchor_cache is not None:
        return _trust_anchor_cache

    if hasattr(sys, '_MEIPASS'):
        internal_path = os.path.join(sys._MEIPASS, 'config', 'rule_update_config.json')
    else:
        internal_path = os.path.join(get_base_dir(), 'config', 'rule_update_config.json')

    if not os.path.exists(internal_path):
        raise FileNotFoundError(
            "번들 내부 config/rule_update_config.json을 찾을 수 없습니다 - "
            "룰셋 업데이트 서명 검증용 신뢰 루트가 없어 업데이트를 진행할 수 없습니다."
        )

    with open(internal_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    _trust_anchor_cache = data["public_key_b64"]
    return _trust_anchor_cache


def _local_manifest_version():
    path = os.path.join(get_base_dir(), 'rules', 'ruleset_manifest.json')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f).get('manifest_version', 0)
    except Exception:
        # 로컬 매니페스트를 못 읽으면 "매우 구버전"으로 취급해, 검증만 통과하면
        # 복구 차원에서 업데이트를 받아들인다.
        return 0


def _fetch_latest_release(timeout):
    url = getattr(AppConfig, "UPDATE_CHECK_URL", "")
    if not url:
        return None
    resp = requests.get(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"Z-VulnScan-RuleUpdater/{AppConfig.VERSION}",
        },
        timeout=timeout,
    )
    if resp.status_code == 404:
        # 아직 릴리즈가 없는 정상 상태 (update_checker.py와 동일한 처리)
        return None
    resp.raise_for_status()
    return resp.json()


def _find_asset_url(release, name):
    for asset in (release.get("assets") or []):
        if asset.get("name") == name:
            return asset.get("browser_download_url")
    return None


def _verify_signature(zip_bytes, sig_b64_text):
    public_key_b64 = _load_trust_anchor()
    pub_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
    signature = base64.b64decode(sig_b64_text.strip())
    pub_key.verify(signature, zip_bytes)  # 실패 시 InvalidSignature 예외


def _safe_extract(zf, dest_dir):
    """[Zip-Slip 방지] 서명 검증을 통과한 zip이라도 멤버 경로에 '..'나 절대경로가
    섞여있으면 dest_dir 밖에 파일을 쓸 수 있다 - Python 버전에 따라 zipfile이
    자체적으로 막아주기도/안 막아주기도 하므로 버전에 기대지 않고 직접 검증한다."""
    dest_dir = os.path.realpath(dest_dir)
    for member in zf.infolist():
        target_path = os.path.realpath(os.path.join(dest_dir, member.filename))
        if not (target_path == dest_dir or target_path.startswith(dest_dir + os.sep)):
            raise ValueError(f"Zip 멤버 경로가 대상 폴더 밖을 가리킵니다(zip-slip 의심): {member.filename}")
    zf.extractall(dest_dir)


def check_and_apply_update(timeout=15):
    """
    Settings에서 명시적으로 켠 경우에만 GitHub 최신 릴리즈를 확인해 룰셋 업데이트를
    받아 적용한다.

    반환: (status, detail)
    status: "DISABLED" | "UP_TO_DATE" | "NO_RELEASE_ASSET" | "VERIFY_FAILED" | "ERROR" | "UPDATED"
    """
    if not load_settings().get("ruleset_auto_update", False):
        return "DISABLED", "설정에서 비활성화되어 있습니다."

    try:
        release = _fetch_latest_release(timeout)
    except Exception as e:
        AppLogger.log_error("[RuleUpdate] Failed to fetch release info", e)
        return "ERROR", f"릴리즈 정보 조회 실패: {e}"

    if not release:
        return "NO_RELEASE_ASSET", "발행된 릴리즈가 없습니다."

    cfg = _load_update_config()
    zip_url = _find_asset_url(release, cfg["asset_zip_name"])
    sig_url = _find_asset_url(release, cfg["asset_sig_name"])
    if not zip_url or not sig_url:
        return "NO_RELEASE_ASSET", "이 릴리즈에는 룰셋 업데이트가 첨부되지 않았습니다."

    try:
        zip_bytes = requests.get(zip_url, timeout=timeout).content
        sig_text = requests.get(sig_url, timeout=timeout).text
    except Exception as e:
        AppLogger.log_error("[RuleUpdate] Failed to download update assets", e)
        return "ERROR", f"다운로드 실패: {e}"

    # [핵심] 서명 검증. 실패하면 무조건 폐기하고 여기서 함수를 끝낸다 -
    # 아래의 압축 해제/파일 반영 코드에는 절대 도달하지 않는다.
    try:
        _verify_signature(zip_bytes, sig_text)
    except Exception as e:
        AppLogger.log_error("[RuleUpdate] Signature verification FAILED - update discarded, no files touched", e)
        return "VERIFY_FAILED", "서명 검증에 실패해 업데이트를 적용하지 않았습니다."

    # 서명 통과 후에만 내용을 열어본다.
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            with zf.open('ruleset_manifest.json') as mf:
                remote_version = json.load(mf).get('manifest_version', 0)

            local_version = _local_manifest_version()
            if remote_version <= local_version:
                return "UP_TO_DATE", f"이미 최신입니다 (로컬 v{local_version})."

            rules_dir = os.path.join(get_base_dir(), 'rules')
            os.makedirs(rules_dir, exist_ok=True)
            _safe_extract(zf, rules_dir)
    except Exception as e:
        AppLogger.log_error("[RuleUpdate] Failed to apply verified update", e)
        return "ERROR", f"검증은 통과했으나 적용 중 오류: {e}"

    return "UPDATED", f"룰셋을 v{local_version} → v{remote_version}으로 업데이트했습니다. 재시작 후 반영됩니다."
