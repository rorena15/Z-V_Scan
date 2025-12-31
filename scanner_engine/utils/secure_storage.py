# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import keyring
import sys

SERVICE_NAME = "Z-VulnScan_Pro"

class SecureStorage:
    @staticmethod
    def save_credential(target, username, password):
        """
        비밀번호를 OS 보안 저장소(Credential Manager)에 저장
        Key: target_ip:username
        """
        if not target or not username or not password:
            return False
        
        key = f"{target}:{username}"
        try:
            keyring.set_password(SERVICE_NAME, key, password)
            return True
        except Exception as e:
            print(f"[SecureStorage] Save Error: {e}")
            return False

    @staticmethod
    def get_credential(target, username):
        """
        저장된 비밀번호를 불러옴 (메모리에 오래 상주시키지 말 것)
        """
        key = f"{target}:{username}"
        try:
            return keyring.get_password(SERVICE_NAME, key)
        except Exception as e:
            print(f"[SecureStorage] Get Error: {e}")
            return None

    @staticmethod
    def delete_credential(target, username):
        """
        스캔 완료 후 비밀번호 삭제 (잔존 정보 제거)
        """
        key = f"{target}:{username}"
        try:
            keyring.delete_password(SERVICE_NAME, key)
        except Exception as e:
            # 삭제할 게 없으면 무시
            pass