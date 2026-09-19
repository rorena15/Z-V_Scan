/*
Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
This software is proprietary and confidential.
Unauthorized copying, modification, distribution, or reverse engineering
of this file, via any medium, is strictly prohibited.
*/
zvsRenderTopbar('account');

function $(id) { return document.getElementById(id); }

document.addEventListener('zvs:ready', function (evt) {
    const roleLabel = { admin: '관리자', operator: '운영자', viewer: '조회자' }[evt.detail.role] || evt.detail.role;
    $('whoBox').textContent = '아이디: ' + evt.detail.username + '  ·  역할: ' + roleLabel;
});

$('btnChangePassword').addEventListener('click', function () {
    const current = $('currentPassword').value;
    const next = $('newPassword').value;
    const confirm = $('confirmPassword').value;
    const msgEl = $('pwMsg');

    if (next.length < 8) {
        msgEl.textContent = '새 비밀번호는 8자 이상이어야 합니다.';
        msgEl.className = 'msg err';
        return;
    }
    if (next !== confirm) {
        msgEl.textContent = '새 비밀번호가 서로 일치하지 않습니다.';
        msgEl.className = 'msg err';
        return;
    }

    zvsFetch('/api/account/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: current, new_password: next, confirm: confirm }),
    })
        .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
        .then(function (r) {
            if (r.status !== 200) {
                msgEl.textContent = r.body.error || '변경 실패';
                msgEl.className = 'msg err';
                return;
            }
            $('currentPassword').value = '';
            $('newPassword').value = '';
            $('confirmPassword').value = '';
            msgEl.textContent = '비밀번호를 변경했습니다.';
            msgEl.className = 'msg ok';
        })
        .catch(function (err) {
            msgEl.textContent = '요청 실패: ' + err;
            msgEl.className = 'msg err';
        });
});

// ------------------------------------------------------------------
// [API 토큰] 발급/폐기는 브라우저 세션에서만 가능(서버가 강제) - 발급 직후 원문을 한 번만 보여준다.
// ------------------------------------------------------------------
function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
const TOKEN_ROLE_LABEL = { operator: '운영자', viewer: '조회자', admin: '관리자' };

function loadTokens() {
    fetch('/api/tokens')
        .then(function (res) { return res.status === 200 ? res.json() : null; })
        .then(function (data) {
            if (!data) return;
            const sel = $('tokenRole');
            if (!sel.dataset.filled) {
                sel.innerHTML = data.allowed_roles.map(function (r) { return '<option value="' + esc(r.value) + '">' + esc(r.label) + '</option>'; }).join('');
                sel.dataset.filled = '1';
            }
            const tbody = $('tokenBody');
            tbody.innerHTML = '';
            $('tokenEmpty').style.display = data.tokens.length ? 'none' : 'block';
            data.tokens.forEach(function (t) {
                const tr = document.createElement('tr');
                tr.innerHTML = '<td>' + esc(t.name) + '</td><td>' + esc(t.owner) + '</td><td>' + esc(TOKEN_ROLE_LABEL[t.role] || t.role) + '</td>' +
                    '<td>' + esc(t.created_at) + '</td><td>' + esc(t.last_used || '-') + '</td>' +
                    '<td><button class="btn btn-danger" data-revoke="' + esc(t.id) + '">폐기</button></td>';
                tbody.appendChild(tr);
            });
            tbody.querySelectorAll('[data-revoke]').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    if (!window.confirm('이 토큰을 폐기합니다. 이 토큰을 쓰는 스크립트는 즉시 동작하지 않게 됩니다.')) return;
                    zvsFetch('/api/tokens/' + encodeURIComponent(btn.getAttribute('data-revoke')), { method: 'DELETE' })
                        .then(function () { loadTokens(); });
                });
            });
        });
}

$('btnCreateToken').addEventListener('click', function () {
    const msg = $('tokenMsg');
    zvsFetch('/api/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: $('tokenName').value.trim(), role: $('tokenRole').value }),
    })
        .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
        .then(function (r) {
            if (r.status !== 200) { msg.textContent = r.body.error || '발급 실패'; msg.className = 'msg err'; return; }
            msg.textContent = '토큰을 발급했습니다.';
            msg.className = 'msg ok';
            $('tokenName').value = '';
            $('tokenValue').textContent = r.body.token;
            $('tokenExample').textContent = 'curl -H "Authorization: Bearer ' + r.body.token.slice(0, 12) + '..." ' + location.origin + '/api/export/findings.csv';
            $('tokenReveal').style.display = 'block';
            loadTokens();
        });
});

loadTokens();
