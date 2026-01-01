# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
class OUILookup:
    # 주요 제조사 OUI 데이터베이스 (하드코딩 예시)
    # 실제 상용화 시에는 oui.txt 파일을 로드하는 방식으로 확장 권장
    _oui_db = {
        "00:50:56": "VMware, Inc.",
        "00:0C:29": "VMware, Inc.",
        "00:05:69": "VMware, Inc.",
        "00:15:5D": "Microsoft Corporation (Hyper-V)",
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Trading Ltd",
        "E4:5F:01": "Raspberry Pi Trading Ltd",
        "00:11:32": "Synology Incorporated",
        "00:1E:8C": "ASUSTek COMPUTER INC.",
        "D8:3A:DD": "Samsung Electronics Co.,Ltd",
        "F0:D2:F1": "Amazon Technologies Inc.",
        "00:D8:61": "Hikvision Digital Technology",
        "A4:2B:B0": "TP-Link",
        "00:1A:11": "Google, Inc.",
        "AC:CF:5C": "Apple, Inc.",
        "00:23:24": "G-Electronics (LG)",
        "00:E0:91": "LG Electronics",
        "E8:03:9A": "IPTIME (EFM Networks)",
        "64:E5:99": "IPTIME (EFM Networks)"
    }

    @staticmethod
    def lookup(mac_address):
        """MAC 주소를 받아 제조사 이름을 반환"""
        if not mac_address or mac_address in ["Unknown", "Localhost"]:
            return "Unknown Vendor"
        
        # MAC 정규화: 대문자 변환, '-'를 ':'로 통일
        mac_clean = mac_address.upper().replace("-", ":")
        
        # 앞 3바이트(XX:XX:XX) 추출
        if len(mac_clean) >= 8:
            oui_prefix = mac_clean[:8]
            return OUILookup._oui_db.get(oui_prefix, "Generic Device")
        
        return "Unknown Vendor"