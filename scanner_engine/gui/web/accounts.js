/*
Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
This software is proprietary and confidential.
Unauthorized copying, modification, distribution, or reverse engineering
of this file, via any medium, is strictly prohibited.
*/
zvsRenderTopbar('accounts');

function $(id) { return document.getElementById(id); }
function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

function showMsg(text, ok) {
    const el = $('accountsMsg');
    el.textContent = text;
    el.className = 'msg ' + (ok ? 'ok' : 'err');
}

function loadAccounts() {
    fetch('/api/accounts')
        .then(function (res) {
            if (res.status === 401 || res.status === 403) { location.href = '/'; return null; }
            return res.json();
        })
        .then(function (data) {
            if (!data) return;
            populateRoleSelect(data.roles);
            renderAccounts(data.accounts, data.current_user);
        });
}

function populateRoleSelect(roles) {
    const select = $('newRole');
    if (select.dataset.filled) return;
    select.innerHTML = roles.map(function (r) {
        return '<option value="' + esc(r.value) + '"' + (r.value === 'operator' ? ' selected' : '') + '>' + esc(r.label) + '</option>';
    }).join('');
    select.dataset.filled = '1';
}

function renderAccounts(accounts, currentUser) {
    const tbody = $('accountsBody');
    tbody.innerHTML = '';
    accounts.forEach(function (a) {
        const isSelf = a.username.toLowerCase() === (currentUser || '').toLowerCase();
        const tr = document.createElement('tr');
        tr.innerHTML =
            '<td>' + esc(a.username) + (isSelf ? '<span class="badge-self">현재 로그인</span>' : '') + '</td>' +
            '<td><span class="badge-role ' + esc(a.role) + '">' + esc(roleLabel(a.role)) + '</span></td>' +
            '<td>' + esc(a.created_at) + '</td>' +
            '<td><button class="btn btn-danger" data-remove="' + esc(a.username) + '"' + (isSelf ? ' disabled title="본인 계정은 삭제할 수 없습니다"' : '') + '>삭제</button></td>';
        tbody.appendChild(tr);
    });
    tbody.querySelectorAll('[data-remove]:not([disabled])').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const username = btn.getAttribute('data-remove');
            if (!confirm("'" + username + "' 계정을 삭제합니다. 계속하시겠습니까?")) return;
            zvsFetch('/api/accounts/' + encodeURIComponent(username), { method: 'DELETE' })
                .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
                .then(function (r) {
                    if (r.status !== 200) { showMsg(r.body.error, false); return; }
                    showMsg("'" + username + "' 계정을 삭제했습니다.", true);
                    loadAccounts();
                });
        });
    });
}

function roleLabel(role) {
    return { admin: '관리자', operator: '운영자', viewer: '조회자' }[role] || role;
}

$('btnAddAccount').addEventListener('click', function () {
    const username = $('newUsername').value.trim();
    const password = $('newPassword').value;
    const confirmPw = $('newPasswordConfirm').value;
    const role = $('newRole').value;

    if (!username) { showMsg('아이디를 입력하세요.', false); return; }
    if (password.length < 8) { showMsg('비밀번호는 8자 이상이어야 합니다.', false); return; }
    if (password !== confirmPw) { showMsg('비밀번호가 서로 일치하지 않습니다.', false); return; }

    zvsFetch('/api/accounts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password, role: role }),
    })
        .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
        .then(function (r) {
            if (r.status !== 200) { showMsg(r.body.error, false); return; }
            $('newUsername').value = '';
            $('newPassword').value = '';
            $('newPasswordConfirm').value = '';
            showMsg("'" + username + "' 계정을 추가했습니다.", true);
            loadAccounts();
        });
});

loadAccounts();

// ------------------------------------------------------------------
// [세션 관리] 접속 중인 세션 목록 + 강제 로그아웃(관리자 전용, 서버가 강제).
// ------------------------------------------------------------------
function loadSessions() {
    fetch('/api/sessions')
        .then(function (res) { return res.status === 200 ? res.json() : null; })
        .then(function (rows) {
            if (!rows) return;
            const tbody = $('sessionsBody');
            tbody.innerHTML = '';
            rows.forEach(function (s) {
                const tr = document.createElement('tr');
                tr.innerHTML =
                    '<td>' + esc(s.username) + (s.is_current ? '<span class="badge-self">현재 세션</span>' : '') + '</td>' +
                    '<td><span class="badge-role ' + esc(s.role) + '">' + esc(roleLabel(s.role)) + '</span></td>' +
                    '<td>' + esc(s.ip) + '</td>' +
                    '<td title="' + esc(s.user_agent) + '">' + esc(s.user_agent.slice(0, 28)) + '</td>' +
                    '<td>' + esc(s.login_at) + '</td><td>' + esc(s.last_seen) + '</td>' +
                    '<td><button class="btn btn-danger" data-kick="' + esc(s.public_id) + '"' + (s.is_current ? ' disabled' : '') + '>강제 로그아웃</button></td>';
                tbody.appendChild(tr);
            });
            tbody.querySelectorAll('[data-kick]:not([disabled])').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    if (!window.confirm('이 세션을 강제로 로그아웃시킵니다. 계속하시겠습니까?')) return;
                    zvsFetch('/api/sessions/' + encodeURIComponent(btn.getAttribute('data-kick')), { method: 'DELETE' })
                        .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
                        .then(function (r) {
                            const el = $('sessionsMsg');
                            el.textContent = r.status === 200 ? '세션을 종료했습니다.' : (r.body.error || '실패');
                            el.className = 'msg ' + (r.status === 200 ? 'ok' : 'err');
                            loadSessions();
                        });
                });
            });
        });
}

$('btnRefreshSessions').addEventListener('click', loadSessions);
loadSessions();
