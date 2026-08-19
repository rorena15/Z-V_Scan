# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import inspect
import secrets
from core.config import AppConfig
# 실제 정품 키

# [버그 수정] 예전엔 frozen(배포용 exe) 빌드에서는 이 검사 자체를 완전히 건너뛰고
# 무조건 진짜 토큰을 반환했다 - "엔진 모듈만 따로 떼어내 악용 방지"라는 이 파일의
# 목적이 정작 실제 배포판(고객에게 나가는 유일한 형태)에서는 아예 동작하지 않는
# 상태였다. 이제 frozen 여부와 무관하게 항상 같은 검증을 거친다.
#
# 파일 경로 문자열에 "scanner_engine"이 포함되는지 보던 예전 방식은, 이 저장소
# 자체가 그 이름의 폴더 안에 있어서 사실상 아무 .py 파일이나 다 통과시키는
# 눈가림 수준의 검사였다 - 대신 호출자의 실제 파이썬 모듈명(__name__)을 정확히
# 매칭한다. 현재 이 함수를 실제로 호출하는 곳은 core/worker.py 단 한 곳뿐이므로
# 허용 목록도 그에 맞춰 최소화한다(전에 있던 audit_runner.py는 저장소에 실제로
# 존재하지 않는 항목이었음).
_ALLOWED_MODULES = {"core.worker"}


def get_engine_token():
    try:
        stack = inspect.stack()
        if len(stack) < 2:
            return _generate_fake_token()

        caller_frame = stack[1]
        caller_module = caller_frame.frame.f_globals.get("__name__", "")

        if caller_module in _ALLOWED_MODULES:
            return AppConfig.ENGINE_ACCESS_TOKEN

        return _generate_fake_token()

    except Exception:
        # 판별 자체가 실패하면 안전한 쪽(가짜 토큰)으로 fail-closed 한다 -
        # 진짜 토큰을 내주는 쪽으로 실패하면 안 된다.
        return _generate_fake_token()


def _generate_fake_token():
    return secrets.token_hex(16)
