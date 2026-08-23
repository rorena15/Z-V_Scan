# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------

import argparse
import hashlib
import json
import random
import string
import sys
import os
from datetime import datetime, timedelta
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from core.config import AppConfig
from core.license_validator import LicenseValidator

# [라이선스 발급 체계] 발급자(본인)가 "누구에게 어떤 키를 언제 발급했는지" 알 수 있도록
# 로컬 대장에 기록한다. 저장소 밖(repo 루트)에 두고 .gitignore 처리 - 고객 정보가
# 담길 수 있는 운영 데이터라 소스 저장소에는 올리지 않는다.
_LEDGER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'issued_licenses.json')


def generate_key(tier_code, valid_days=365):
    """
    지정된 등급(STD, PRO, ENT)의 정품 라이선스 키를 생성합니다.
    valid_days: 오늘부터 며칠간 유효한지 (기본 1년)
    """
    # 1. 4자리 랜덤 문자열 (A-Z, 0-9)
    random_val = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

    # 2. 만료일 -> 난독화 토큰 (평문 YYYYMMDD로 넣으면 키만 봐도 발급/만료 패턴이
    # 그대로 드러나므로, salt로 XOR한 4자리 hex 토큰으로 대신 넣는다)
    expiry_date = (datetime.now() + timedelta(days=valid_days)).date()
    expiry_token = LicenseValidator.encode_expiry_token(expiry_date)

    # 2.5 등급 -> 난독화 토큰 (예전엔 "ZV3-ENT-..."처럼 평문이라 키만 봐도 등급이
    # 바로 드러났다. 만료일과 같은 방식으로 감춰서 키만 봐서는 무슨 등급인지 유추할
    # 수 없게 한다 - license_validator.py._decode_tier_token()이 이걸 되돌린다.)
    tier_token = LicenseValidator.encode_tier_token(tier_code)

    # 3. 해시 계산 (Tier Token + Expiry Token + Random + Salt)
    raw_str = f"{tier_token}{expiry_token}{random_val}{AppConfig.LICENSE_SALT}"
    checksum = hashlib.md5(raw_str.encode()).hexdigest()[:4].upper()

    # 4. 키 조합 - 접두어도 "ZV3"(제품명 이니셜+버전) 평문 대신 난독화된 태그를 쓴다.
    # 등급/만료일을 감춰도 앞자리가 "ZV3"로 그대로면 이게 Z-VulnScan 키라는 것
    # 자체는 누구나 바로 알 수 있어서, 5개 구간 어디에도 읽어서 뜻이 통하는 조각이
    # 남지 않게 통일했다.
    prefix = LicenseValidator.key_prefix()
    return f"{prefix}-{tier_token}-{expiry_token}-{random_val}-{checksum}", expiry_date


def _load_ledger():
    if not os.path.exists(_LEDGER_PATH):
        return []
    try:
        with open(_LEDGER_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def _log_issued_key(key, tier_code, expiry_date, label):
    ledger = _load_ledger()
    ledger.append({
        "key": key,
        "tier": tier_code,
        "expiry": expiry_date.isoformat(),
        "issued_at": datetime.now().isoformat(timespec='seconds'),
        "label": label or "",
    })
    with open(_LEDGER_PATH, 'w', encoding='utf-8') as f:
        json.dump(ledger, f, ensure_ascii=False, indent=2)


def _cmd_generate(args):
    # [2026-08-20] 발급일 기준 만료(키 자체에 절대 만료일이 박힘)라서, 발급 시점과
    # 고객이 실제로 등록하는 시점 사이에 시차가 생기면 그만큼 실사용 기간이 약속한
    # 기간보다 줄어드는 손해가 생길 수 있다. 등록 시점 기준으로 바꾸는 방법도
    # 검토했으나, 그러려면 최초 활성화 시점을 로컬에 저장해야 하는데 이 프로젝트는
    # 라이선스 서버 없이 완전 오프라인 검증이 전제라 그 저장값을 지우고 재설치하면
    # 기간이 통째로 초기화되는 더 큰 구멍이 생긴다. 그래서 구조는 그대로 두고,
    # --days(고객에게 약속한 기간)에 --grace-days(발급~등록 지연을 흡수하는 여유
    # 기간, 기본 7일)를 더해서 실제 키의 만료일을 계산하는 절차로 대응한다.
    total_days = args.days + args.grace_days
    key, expiry_date = generate_key(args.tier, total_days)
    _log_issued_key(key, args.tier, expiry_date, args.label)
    print(f"발급된 키: {key}")
    print(f"등급: {args.tier} / 약속 기간: {args.days}일 (+그레이스 {args.grace_days}일) / "
          f"실제 만료일: {expiry_date} / 라벨: {args.label or '(없음)'}")
    print(f"(발급 대장에 기록됨: {os.path.abspath(_LEDGER_PATH)})")


def _cmd_revoke(args):
    if LicenseValidator.revoke_key(args.key):
        print(f"취소 처리 완료: {args.key}")
        print(f"(취소 목록: {LicenseValidator._get_revoked_list_path()})")
        print("이 취소는 프로그램을 재빌드/재배포해야 실제로 적용됩니다.")
    else:
        print("키 형식이 올바르지 않아 취소하지 못했습니다.")


def _cmd_list_issued(args):
    ledger = _load_ledger()
    if not ledger:
        print("발급 이력이 없습니다.")
        return
    for entry in ledger:
        print(f"{entry['issued_at']}  [{entry['tier']}]  만료:{entry['expiry']}  라벨:{entry['label'] or '-'}  {entry['key']}")


def _cmd_list_revoked(args):
    revoked = LicenseValidator.list_revoked()
    if not revoked:
        print("취소된 키가 없습니다.")
        return
    for random_val in revoked:
        print(random_val)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Z-VulnScan License Generator/Manager")
    sub = parser.add_subparsers(dest="command")

    p_gen = sub.add_parser("generate", help="새 라이선스 키 발급")
    p_gen.add_argument("--tier", choices=["STD", "PRO", "ENT"], required=True)
    p_gen.add_argument("--days", type=int, default=365, help="고객에게 약속한 유효기간(일), 기본 365일")
    p_gen.add_argument("--grace-days", type=int, default=7,
                        help="발급~등록 사이 지연을 흡수하는 여유 기간(일), 기본 7일 - "
                             "실제 만료일 = 발급일 + days + grace-days")
    p_gen.add_argument("--label", type=str, default="", help="발급 대상 메모(예: 고객사명)")
    p_gen.set_defaults(func=_cmd_generate)

    p_revoke = sub.add_parser("revoke", help="발급된 키를 취소 목록에 추가")
    p_revoke.add_argument("--key", type=str, required=True)
    p_revoke.set_defaults(func=_cmd_revoke)

    p_list = sub.add_parser("list-issued", help="지금까지 발급한 키 이력 조회")
    p_list.set_defaults(func=_cmd_list_issued)

    p_list_rv = sub.add_parser("list-revoked", help="취소된 키 목록 조회")
    p_list_rv.set_defaults(func=_cmd_list_revoked)

    args = parser.parse_args()

    if args.command is None:
        # 서브커맨드 없이 그냥 실행하면(기존 동작 유지) 데모용으로 3개 등급 키를 보여준다
        print("="*40)
        print(" 🛡️  Z-VulnScan License Generator")
        print("="*40)
        for tier in ("STD", "PRO", "ENT"):
            key, expiry_date = generate_key(tier)
            print(f" [{tier}] : {key}  (만료: {expiry_date})")
        print("="*40)
        print("실제 발급/취소/이력조회는 아래처럼 서브커맨드를 사용하세요:")
        print("  python keygen.py generate --tier PRO --days 365 --label \"고객사명\"")
        print("  python keygen.py revoke --key <발급된 키 전체>")
        print("  python keygen.py list-issued")
        print("  python keygen.py list-revoked")
    else:
        args.func(args)