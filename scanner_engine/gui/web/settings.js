/*
Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
This software is proprietary and confidential.
Unauthorized copying, modification, distribution, or reverse engineering
of this file, via any medium, is strictly prohibited.
*/
zvsRenderTopbar('settings');

function $(id) { return document.getElementById(id); }
function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

function showMsg(el, text, ok) {
    el.textContent = text;
    el.className = 'msg ' + (ok ? 'ok' : 'err');
}

function loadSettings() {
    fetch('/api/settings')
        .then(function (res) {
            if (res.status === 401) { location.href = '/login'; return null; }
            return res.json();
        })
        .then(function (data) {
            if (!data) return;
            $('logRetention').value = data.log_retention_days;
            $('theme').value = data.theme;
            $('reportDir').value = data.report_output_dir;

            const lic = data.license;
            $('licenseInfo').textContent = '현재 등급: ' + lic.tier +
                (lic.expiry_date ? ' (만료일: ' + lic.expiry_date + ')' : ' (등록된 키 없음)') +
                ' · Excel 내보내기: ' + (lic.can_export_excel ? '가능' : '불가');

            renderKnownHosts(data.known_hosts);
        });
}

function renderKnownHosts(hosts) {
    const tbody = $('knownHostsBody');
    tbody.innerHTML = '';
    if (!hosts.length) {
        tbody.innerHTML = '<tr><td colspan="3" style="color:var(--text-muted);">등록된 호스트 키가 없습니다.</td></tr>';
        return;
    }
    hosts.forEach(function (h) {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td>' + esc(h.hostname) + '</td><td>' + esc(h.key_types.join(', ')) + '</td>' +
            '<td><button class="btn btn-secondary" data-remove="' + esc(h.hostname) + '" style="padding:4px 10px;font-size:11px;">삭제</button></td>';
        tbody.appendChild(tr);
    });
    tbody.querySelectorAll('[data-remove]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const hostname = btn.getAttribute('data-remove');
            if (!confirm(hostname + '의 저장된 호스트 키를 삭제합니다.\n이후 이 IP로 접속하면 새 호스트 키를 다시 최초 등록합니다.')) return;
            zvsFetch('/api/settings/known-hosts/' + encodeURIComponent(hostname), { method: 'DELETE' })
                .then(function () { loadSettings(); });
        });
    });
}

$('btnSaveGeneral').addEventListener('click', function () {
    zvsFetch('/api/settings/general', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            log_retention_days: $('logRetention').value,
            theme: $('theme').value,
            report_output_dir: $('reportDir').value,
        }),
    })
        .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
        .then(function (r) {
            showMsg($('generalMsg'), r.status === 200 ? '저장했습니다.' : (r.body.error || '저장 실패'), r.status === 200);
        });
});

$('btnPurge').addEventListener('click', function () {
    const days = $('logRetention').value;
    if (!confirm(days + '일보다 오래된 스캔 이력을 삭제합니다. 계속하시겠습니까?')) return;
    zvsFetch('/api/settings/purge-history', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ days: days }),
    })
        .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
        .then(function (r) {
            showMsg($('generalMsg'), r.status === 200 ? (r.body.deleted + '건 정리했습니다.') : (r.body.error || '정리 실패'), r.status === 200);
        });
});

$('btnActivate').addEventListener('click', function () {
    const key = $('licenseKey').value.trim();
    if (!key) { showMsg($('licenseMsg'), '라이선스 키를 입력하세요.', false); return; }
    zvsFetch('/api/settings/license/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: key }),
    })
        .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
        .then(function (r) {
            if (r.status !== 200) { showMsg($('licenseMsg'), r.body.error, false); return; }
            $('licenseKey').value = '';
            showMsg($('licenseMsg'), '활성화되었습니다. (' + r.body.tier + ')', true);
            loadSettings();
        });
});

$('btnDeleteLicense').addEventListener('click', function () {
    if (!confirm('등록된 라이선스 키를 삭제합니다. 삭제 후에는 Standard 등급으로 동작합니다.\n계속하시겠습니까?')) return;
    zvsFetch('/api/settings/license', { method: 'DELETE' })
        .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
        .then(function (r) {
            showMsg($('licenseMsg'), r.status === 200 ? '삭제했습니다.' : (r.body.error || '삭제 실패'), r.status === 200);
            loadSettings();
        });
});

$('btnClearHosts').addEventListener('click', function () {
    if (!confirm('등록된 모든 SSH 호스트 키를 삭제합니다. 계속하시겠습니까?')) return;
    zvsFetch('/api/settings/known-hosts', { method: 'DELETE' })
        .then(function () { loadSettings(); });
});

// ------------------------------------------------------------------
// [관리자 작업 감사로그] utils/web_audit_log.py가 쌓는 이벤트를 최신순으로
// 보여준다 - 조회 전용(쓰기 API 없음)이라 zvsFetch 없이 그냥 fetch로 충분하다.
// ------------------------------------------------------------------
const AUDIT_ACTION_LABEL = {
    login_success: '로그인 성공', login_failed: '로그인 실패', logout: '로그아웃',
    account_create: '계정 생성', account_delete: '계정 삭제', password_change_self: '본인 비밀번호 변경',
    settings_update: '설정 변경', purge_history: '이력 정리', known_host_remove: '호스트 키 삭제',
    known_hosts_clear: '호스트 키 전체 초기화', license_activate: '라이선스 활성화', license_delete: '라이선스 삭제',
    asset_update: '자산 수정', asset_delete: '자산 삭제', waiver_set: '예외처리', waiver_clear: '예외 해제',
    scan_start: '스캔 시작', scan_stop: '스캔 중지', report_generate: '리포트 생성', server_shutdown: '서버 종료',
    api_token_create: 'API 토큰 발급', api_token_revoke: 'API 토큰 폐기', session_revoke: '세션 강제 로그아웃',
    export_findings_csv: 'findings CSV 내보내기',
};

function loadAuditLog() {
    fetch('/api/audit-log?limit=100')
        .then(function (res) { return res.status === 200 ? res.json() : []; })
        .then(function (entries) {
            const tbody = $('auditLogBody');
            tbody.innerHTML = '';
            $('auditLogEmpty').style.display = entries.length ? 'none' : 'block';
            entries.forEach(function (e) {
                const tr = document.createElement('tr');
                const label = AUDIT_ACTION_LABEL[e.action] || e.action;
                tr.innerHTML =
                    '<td>' + esc(e.ts) + '</td>' +
                    '<td>' + esc(e.actor) + (e.role ? ' [' + esc(e.role) + ']' : '') + '</td>' +
                    '<td>' + esc(label) + '</td>' +
                    '<td>' + esc(e.detail) + '</td>';
                tbody.appendChild(tr);
            });
        })
        .catch(function () {});
}

$('btnRefreshAuditLog').addEventListener('click', loadAuditLog);
loadAuditLog();

loadSettings();

function loadThirdParty() {
    fetch('/api/licenses/third-party')
        .then(function (res) { return res.status === 200 ? res.json() : { packages: [] }; })
        .then(function (data) {
            const box = $('thirdPartyList');
            const pkgs = data.packages || [];
            if (!pkgs.length) { box.textContent = '오픈소스 라이선스 목록 파일을 찾지 못했습니다.'; return; }
            box.innerHTML = pkgs.map(function (p) {
                const body = (p.homepage ? '홈페이지: ' + p.homepage + '\n\n' : '') +
                    (p.text || '(패키지에 라이선스 전문 파일이 포함돼 있지 않습니다. 홈페이지에서 확인하세요.)');
                return '<details style="margin-bottom:4px;"><summary style="cursor:pointer;font-size:12.5px;">' +
                    esc(p.name) + ' ' + esc(p.version) + ' <span class="badge">' + esc(p.license) + '</span></summary>' +
                    '<pre style="white-space:pre-wrap;font-size:11px;max-height:260px;overflow:auto;background:var(--surface-1);padding:8px;border-radius:8px;">' +
                    esc(body) + '</pre></details>';
            }).join('');
        })
        .catch(function () {});
}
loadThirdParty();
