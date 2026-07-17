# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[OUI 확장] 예전엔 19개만 하드코딩돼 있어서 실제 현장 장비 태반이 그냥
"Generic Device"로 뭉뚱그려졌다. IEEE 공식 MA-L(24비트 OUI) 전체 등록부를
`rules/oui_database.txt`(OUI 6자리 hex + 탭 + 제조사명, 약 4만 건)로 내려받아
번들하고, 그걸 그대로 불러와 쓰도록 교체했다. 점검 명령어(rules/*.json)와
같은 위치 규칙(외부 rules 폴더 우선, PyInstaller 번들 경로 폴백)을 그대로 쓴다.
"""
import os
import sys

class OUILookup:
    _oui_db = None  # 최초 조회 시 1회만 로드 (지연 로딩)

    @staticmethod
    def _get_db_path():
        filename = "oui_database.txt"
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        external_path = os.path.join(base_dir, 'rules', filename)

        internal_path = None
        if hasattr(sys, '_MEIPASS'):
            internal_path = os.path.join(sys._MEIPASS, 'rules', filename)
        else:
            internal_path = external_path

        if os.path.exists(external_path):
            return external_path
        elif internal_path and os.path.exists(internal_path):
            return internal_path
        return external_path

    @classmethod
    def _load_db(cls):
        cls._oui_db = {}
        path = cls._get_db_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.rstrip('\n')
                    if not line or '\t' not in line:
                        continue
                    oui, name = line.split('\t', 1)
                    cls._oui_db[oui] = name
        except Exception:
            cls._oui_db = {}

    @staticmethod
    def lookup(mac_address):
        """MAC 주소를 받아 제조사 이름을 반환"""
        if not mac_address or mac_address in ["Unknown", "Localhost"]:
            return "Unknown Vendor"

        if OUILookup._oui_db is None:
            OUILookup._load_db()

        # MAC 정규화: 대문자 변환, '-'를 ':'로 통일
        mac_clean = mac_address.upper().replace("-", ":")

        # 앞 3바이트(XX:XX:XX) 추출 후 콜론 제거(DB 키는 "AABBCC" 형식)
        if len(mac_clean) >= 8:
            oui_prefix = mac_clean[:8].replace(":", "")
            return OUILookup._oui_db.get(oui_prefix, "Generic Device")

        return "Unknown Vendor"
