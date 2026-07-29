# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import time


class AdaptiveThrottle:
    """
    OT/레거시 환경 보호용 적응형 스로틀링.
    직전 명령의 응답 소요시간을 보고 다음 명령 실행 전 대기시간을 자동 조절한다.
    - 응답이 느려지면(SLOW_THRESHOLD 초과) 대기시간을 늘림 (최대 MAX_DELAY까지)
    - 응답이 빠르면 base_delay까지 서서히 줄여 원래 속도로 회복
    enabled=False면 항상 대기 없음 (기존 동작과 100% 동일, 하위 호환)
    """
    SLOW_THRESHOLD = 2.0   # 초. 이보다 응답이 느리면 서버가 부담을 느낀다고 판단
    MAX_DELAY = 5.0        # 초. 최대 대기 시간 상한
    GROWTH_FACTOR = 2.0    # 느려지면 대기시간을 2배로 증가
    DECAY_FACTOR = 0.5     # 빨라지면 대기시간을 절반으로 감소 (base_delay 밑으로는 안 내려감)

    def __init__(self, enabled=False, base_delay=0.3):
        self.enabled = enabled
        self.base_delay = base_delay if enabled else 0.0
        self.current_delay = self.base_delay

    def wait(self, elapsed):
        """직전 명령 실행 소요시간(elapsed, 초)을 보고 다음 명령 전 대기 여부를 결정한다."""
        if not self.enabled:
            return

        if elapsed > self.SLOW_THRESHOLD:
            self.current_delay = min((self.current_delay or self.base_delay) * self.GROWTH_FACTOR, self.MAX_DELAY)
        else:
            self.current_delay = max(self.current_delay * self.DECAY_FACTOR, self.base_delay)

        if self.current_delay > 0:
            time.sleep(self.current_delay)
