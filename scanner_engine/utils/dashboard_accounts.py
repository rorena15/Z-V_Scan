# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[웹 대시보드 로그인 계정] 데스크톱 앱과 별개로, 웹 대시보드 모드(web_dashboard_server.py)
로그인에만 쓰이는 계정 저장소. 여러 명이 각자 아이디로 로그인할 수 있도록 config/
dashboard_accounts.json에 계정 목록을 저장한다 - app_settings.py와 같은 base_dir
해석 방식을 공유한다.

비밀번호는 bcrypt(이미 requirements.txt에 있는 의존성 - license_validator 등에서
쓰지는 않지만 paramiko가 선택적으로 끌어오는 것과 별개로, 여기서 직접 해시용으로
쓴다)로 해시해서 저장하고 평문은 어디에도 남기지 않는다.

이 파일(dashboard_accounts.json)은 .gitignore에 등록돼 있다 - known_hosts와
마찬가지로 실제 배포 사이트마다 달라지는 로컬 전용 자격증명이기 때문.

[권한 분리, 2026-09 확장] 처음엔 계정 전부가 동일한 권한(사실상 전부 관리자)이었는데,
스캔 실행/자산·Waiver 편집/설정·계정 관리처럼 파급력이 다른 작업을 같은 등급으로
묶어두는 게 안전하지 않다는 지적으로 3단계 역할을 추가했다:
- admin(관리자): 전부 가능 - 설정, 계정 관리(다른 계정 추가/삭제) 포함
- operator(운영자): 스캔 실행/중지, 자산 편집·삭제, Waiver 처리, 리포트 생성까지 -
  설정/계정 관리만 제외
- viewer(조회자): 대시보드·도움말·자산 목록 등 조회만, 쓰기 동작 전부 불가
역할 판정/차단은 web_dashboard_server.py의 라우트 데코레이터(_require_role)가
전담한다 - 이 파일은 저장/검증만 책임진다.
"""
import os
import sys
import json
import hashlib
import hmac
import secrets
import threading
from datetime import datetime

import bcrypt

_lock = threading.Lock()

ROLES = ("admin", "operator", "viewer")
ROLE_LABELS = {"admin": "관리자", "operator": "운영자", "viewer": "조회자"}
# 등급 비교(A가 B 이상의 권한인지)에 쓰는 순위 - 숫자가 클수록 강한 권한.
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}
DEFAULT_ROLE = "operator"


def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _get_accounts_path():
    config_dir = os.path.join(get_base_dir(), 'config')
    try:
        os.makedirs(config_dir, exist_ok=True)
    except OSError:
        pass
    return os.path.join(config_dir, 'dashboard_accounts.json')


def _normalize_role(role):
    """저장된/입력된 role 값을 검증한다. 없거나 알 수 없는 값이면(2026-09 이전에
    role 필드 없이 만들어진 기존 계정 포함) admin으로 취급한다 - 권한 분리 도입
    전에는 전원이 사실상 관리자였으므로, 기존 계정의 접근 범위가 갑자기 좁아져
    "설정에 못 들어간다"는 혼란을 주지 않기 위한 하위호환 기본값이다."""
    return role if role in ROLES else "admin"


def load_accounts():
    path = _get_accounts_path()
    if not os.path.exists(path):
        return []
    try:
        with _lock:
            with open(path, 'r', encoding='utf-8') as f:
                accounts = json.load(f).get('accounts', [])
    except Exception:
        return []
    for account in accounts:
        account['role'] = _normalize_role(account.get('role'))
    return accounts


def _save_accounts(accounts):
    path = _get_accounts_path()
    try:
        with _lock:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump({'accounts': accounts}, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def has_any_account():
    return len(load_accounts()) > 0


def list_usernames():
    return [a['username'] for a in load_accounts()]


def _admin_count(accounts):
    return sum(1 for a in accounts if _normalize_role(a.get('role')) == 'admin')


def create_account(username, password, role=DEFAULT_ROLE):
    """반환: (성공여부, 에러메시지|None). 아이디 대소문자는 구분하지 않는다.
    최초 계정(이 서버에 계정이 하나도 없는 상태)은 role 인자와 무관하게 항상
    admin으로 만든다 - 그렇지 않으면 아무도 설정/계정 관리에 접근할 수 없는
    상태로 서버가 시작될 수 있다."""
    username = (username or '').strip()
    if not username:
        return False, "아이디를 입력하세요."
    if len(password or '') < 8:
        return False, "비밀번호는 8자 이상이어야 합니다."

    accounts = load_accounts()
    if any(a['username'].lower() == username.lower() for a in accounts):
        return False, "이미 존재하는 아이디입니다."

    role = "admin" if not accounts else _normalize_role(role)

    pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    accounts.append({
        'username': username,
        'password_hash': pw_hash,
        'role': role,
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    })
    if not _save_accounts(accounts):
        return False, "계정 저장에 실패했습니다."
    return True, None


def delete_account(username):
    """반환: (성공여부, 에러메시지|None).
    - 마지막 남은 계정은 삭제할 수 없다(웹 대시보드에 아무도 로그인할 수 없는
      상태가 되는 걸 방지).
    - 마지막 남은 admin 계정도 삭제할 수 없다(operator/viewer만 남으면 이후
      설정/계정 관리에 아무도 접근할 수 없어 사실상 잠기게 된다) - 자기 자신
      삭제 금지(로그인 세션 인지가 필요해 웹 라우트 쪽에서 처리)와는 별개의 가드."""
    accounts = load_accounts()
    if len(accounts) <= 1:
        return False, "마지막 남은 계정은 삭제할 수 없습니다."

    target = next((a for a in accounts if a['username'].lower() == (username or '').lower()), None)
    if target is None:
        return False, "해당 계정을 찾을 수 없습니다."

    if _normalize_role(target.get('role')) == 'admin' and _admin_count(accounts) <= 1:
        return False, "마지막 남은 관리자 계정은 삭제할 수 없습니다."

    remaining = [a for a in accounts if a is not target]
    if not _save_accounts(remaining):
        return False, "계정 삭제에 실패했습니다."
    _revoke_tokens_of_owner(target['username'])
    return True, None


def verify_login(username, password):
    """반환: (성공여부, role|None)."""
    username = (username or '').strip()
    for account in load_accounts():
        if account['username'].lower() == username.lower():
            try:
                ok = bcrypt.checkpw((password or '').encode('utf-8'), account['password_hash'].encode('utf-8'))
            except Exception:
                return False, None
            return (ok, account['role']) if ok else (False, None)
    return False, None


def change_password(username, current_password, new_password):
    """[본인 비밀번호 변경] 관리자가 계정을 지웠다 새로 만들지 않아도 되도록,
    로그인한 본인이 직접 비밀번호를 바꿀 수 있게 한다. 반드시 현재 비밀번호를
    한 번 더 확인한다 - 로그인 세션을 탈취한 것만으로 다른 사람이 비밀번호를
    바꿔서 원래 계정 주인을 완전히 쫓아내는 걸 막기 위함(세션 쿠키 하나만으로는
    부족하고 비밀번호를 알아야 바꿀 수 있음).
    반환: (성공여부, 에러메시지|None)."""
    username = (username or '').strip()
    if len(new_password or '') < 8:
        return False, "새 비밀번호는 8자 이상이어야 합니다."

    accounts = load_accounts()
    target = next((a for a in accounts if a['username'].lower() == username.lower()), None)
    if target is None:
        return False, "계정을 찾을 수 없습니다."

    try:
        current_ok = bcrypt.checkpw((current_password or '').encode('utf-8'), target['password_hash'].encode('utf-8'))
    except Exception:
        current_ok = False
    if not current_ok:
        return False, "현재 비밀번호가 일치하지 않습니다."

    target['password_hash'] = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    if not _save_accounts(accounts):
        return False, "비밀번호 저장에 실패했습니다."
    return True, None


# ----------------------------------------------------------------------
# [API 토큰] 브라우저 로그인 없이 크론/CI 같은 외부 스크립트가 웹 대시보드 API를
# 쓸 수 있게 하는 개인 액세스 토큰(Authorization: Bearer <토큰>). 토큰 원문은 발급
# 직후 한 번만 보여주고 저장하지 않는다 - SHA-256 해시만 config/api_tokens.json에
# 남긴다(비밀번호가 아니라 32바이트 난수라 bcrypt 같은 느린 해시는 불필요).
# 안전장치: (1) 토큰 역할은 operator까지만 - 설정/계정 관리(admin)는 브라우저 세션으로만
# 가능. (2) 발급자의 현재 역할보다 높을 수 없고, 발급자 역할이 나중에 내려가거나 계정이
# 삭제되면 그에 맞춰 즉시 따라간다(토큰 자체 role과 소유자 현재 role 중 낮은 쪽 적용).
# (3) 비밀번호 변경/토큰 발급 같은 자격증명 관련 동작은 토큰으로 할 수 없다(라우트 쪽 강제).
# ----------------------------------------------------------------------
TOKEN_MAX_ROLE = "operator"
_TOKEN_LAST_USED_WRITE_INTERVAL = 60  # 초 - 매 요청마다 파일을 쓰지 않도록 쓰로틀


def _get_tokens_path():
    config_dir = os.path.join(get_base_dir(), 'config')
    try:
        os.makedirs(config_dir, exist_ok=True)
    except OSError:
        pass
    return os.path.join(config_dir, 'api_tokens.json')


def _load_tokens():
    path = _get_tokens_path()
    if not os.path.exists(path):
        return []
    try:
        with _lock:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f).get('tokens', [])
    except Exception:
        return []


def _save_tokens(tokens):
    path = _get_tokens_path()
    try:
        with _lock:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump({'tokens': tokens}, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def _hash_token(plaintext):
    return hashlib.sha256((plaintext or '').encode('utf-8')).hexdigest()


def _revoke_tokens_of_owner(owner):
    tokens = _load_tokens()
    remaining = [t for t in tokens if t['owner'].lower() != (owner or '').lower()]
    if len(remaining) != len(tokens):
        _save_tokens(remaining)


def _public_token(t):
    return {k: t.get(k) for k in ('id', 'name', 'owner', 'role', 'created_at', 'last_used')}


def create_api_token(owner, name, role):
    """반환: (성공여부, 에러메시지|None, 토큰원문|None, 메타|None). 토큰 원문은 여기서만
    반환되고 이후 어디에도 저장/재조회되지 않는다."""
    name = (name or '').strip()
    if not name or len(name) > 40:
        return False, "토큰 이름은 1~40자여야 합니다.", None, None
    if role not in ROLES or ROLE_RANK[role] > ROLE_RANK[TOKEN_MAX_ROLE]:
        return False, "토큰 역할은 조회자 또는 운영자만 가능합니다.", None, None
    owner_acc = next((a for a in load_accounts() if a['username'].lower() == (owner or '').lower()), None)
    if owner_acc is None:
        return False, "발급자 계정을 찾을 수 없습니다.", None, None
    if ROLE_RANK[role] > ROLE_RANK[owner_acc['role']]:
        return False, "본인 역할보다 높은 권한의 토큰은 발급할 수 없습니다.", None, None

    plaintext = "zvs_" + secrets.token_urlsafe(32)
    entry = {
        'id': secrets.token_hex(4),
        'name': name,
        'owner': owner_acc['username'],
        'role': role,
        'token_hash': _hash_token(plaintext),
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'last_used': None,
    }
    tokens = _load_tokens()
    tokens.append(entry)
    if not _save_tokens(tokens):
        return False, "토큰 저장에 실패했습니다.", None, None
    return True, None, plaintext, _public_token(entry)


def list_api_tokens(owner=None):
    tokens = _load_tokens()
    if owner is not None:
        tokens = [t for t in tokens if t['owner'].lower() == owner.lower()]
    return [_public_token(t) for t in tokens]


def revoke_api_token(token_id, requester, is_admin=False):
    """반환: (성공여부, 에러메시지|None). 본인 토큰만 폐기 가능(관리자는 전부)."""
    tokens = _load_tokens()
    target = next((t for t in tokens if t['id'] == token_id), None)
    if target is None:
        return False, "토큰을 찾을 수 없습니다."
    if not is_admin and target['owner'].lower() != (requester or '').lower():
        return False, "다른 사용자의 토큰은 폐기할 수 없습니다."
    remaining = [t for t in tokens if t is not target]
    if not _save_tokens(remaining):
        return False, "토큰 폐기에 실패했습니다."
    return True, None


def verify_api_token(plaintext):
    """반환: {"username","role","token_id","token_name"} 또는 None. role은 토큰 자체
    역할과 소유자의 '현재' 역할 중 낮은 쪽이다."""
    if not plaintext or not plaintext.startswith("zvs_"):
        return None
    digest = _hash_token(plaintext)
    tokens = _load_tokens()
    match = next((t for t in tokens if hmac.compare_digest(t.get('token_hash', ''), digest)), None)
    if match is None:
        return None
    owner_acc = next((a for a in load_accounts() if a['username'].lower() == match['owner'].lower()), None)
    if owner_acc is None:
        return None
    role = match['role'] if ROLE_RANK[match['role']] <= ROLE_RANK[owner_acc['role']] else owner_acc['role']

    now = datetime.now()
    last = match.get('last_used')
    stale = True
    if last:
        try:
            stale = (now - datetime.strptime(last, '%Y-%m-%d %H:%M:%S')).total_seconds() > _TOKEN_LAST_USED_WRITE_INTERVAL
        except ValueError:
            stale = True
    if stale:
        match['last_used'] = now.strftime('%Y-%m-%d %H:%M:%S')
        _save_tokens(tokens)
    return {"username": owner_acc['username'], "role": role, "token_id": match['id'], "token_name": match['name']}
