/*
Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
This software is proprietary and confidential.
Unauthorized copying, modification, distribution, or reverse engineering
of this file, via any medium, is strictly prohibited.

[웹 대시보드 - 엔진 구동] /api/scan/start로 core/worker.py.ScanWorker를 그대로
띄우고, /api/scan/stream(SSE)으로 로그/진행률을 실시간 푸시받는다. 스트림을 못 쓰는
환경이면 /api/scan/status 1초 폴링으로 자동 폴백한다.
*/
zvsRenderTopbar('scan');

let currentMode = 'NETWORK_SCAN';
let pollTimer = null;
let logSinceIndex = 0;

function $(id) { return document.getElementById(id); }

function setMode(mode) {
    currentMode = mode;
    $('tabNetwork').classList.toggle('active', mode === 'NETWORK_SCAN');
    $('tabAudit').classList.toggle('active', mode === 'AUDIT_VULN');
    $('networkFields').classList.toggle('hidden', mode !== 'NETWORK_SCAN');
    $('auditFields').classList.toggle('hidden', mode !== 'AUDIT_VULN');
}

$('tabNetwork').addEventListener('click', function () { setMode('NETWORK_SCAN'); });
$('tabAudit').addEventListener('click', function () { setMode('AUDIT_VULN'); });

$('portMode').addEventListener('change', function () {
    $('customPortsWrap').classList.toggle('hidden', this.value !== 'custom');
});

function appendLogLines(lines) {
    if (!lines || !lines.length) return;
    const box = $('logConsole');
    const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 10;
    lines.forEach(function (line) {
        box.textContent += line + '\n';
    });
    if (atBottom) box.scrollTop = box.scrollHeight;
}

function updateStatus(state) {
    const badge = $('statusBadge');
    if (state.running) {
        badge.textContent = '실행 중';
        badge.className = 'status-badge running';
        $('btnStart').disabled = true;
        $('btnStop').disabled = false;
    } else {
        badge.textContent = state.finished_reason ? '완료' : '대기 중';
        badge.className = state.finished_reason ? 'status-badge done' : 'status-badge idle';
        $('btnStart').disabled = false;
        $('btnStop').disabled = true;
    }
    if (window.ZVS_ROLE === 'viewer') {
        // 상태가 갱신될 때마다 위 분기가 버튼을 다시 켜므로, 조회 전용 계정은 매번 다시 잠근다.
        $('btnStart').disabled = true;
        $('btnStop').disabled = true;
    }
    const parts = [];
    if (state.target) parts.push('대상: ' + state.target);
    if (state.total) parts.push('진행 ' + state.current + '/' + state.total);
    if (state.assets_found) parts.push('발견된 자산 ' + state.assets_found + '개');
    if (state.finished_reason) parts.push('결과: ' + state.finished_reason);
    $('statusText').textContent = parts.join('  ·  ');
    $('progressFill').style.width = (state.percent || 0) + '%';
}

function poll() {
    fetch('/api/scan/status?since=' + logSinceIndex)
        .then(function (res) {
            if (res.status === 401) { location.href = '/login'; return null; }
            return res.json();
        })
        .then(function (data) {
            if (!data) return;
            appendLogLines(data.log_lines);
            logSinceIndex = data.log_total;
            updateStatus(data.state);
        })
        .catch(function () {});
}

function startPolling() {
    if (pollTimer) return;
    poll();
    pollTimer = setInterval(poll, 1000);
}

// [실시간 스트리밍] 서버의 SSE(/api/scan/stream)로 로그/진행률을 푸시받는다 - 폴링(1초)
// 대신 바뀌는 즉시 도착한다. EventSource는 끊기면 브라우저가 알아서 재연결하지만, 서버가
// 세션을 끊었거나(401) 프록시 등으로 스트림이 막히는 환경이면 계속 실패하므로, 에러가
// 나면 스트림을 닫고 기존 폴링으로 폴백한다.
let stream = null;
function startStream() {
    if (stream || pollTimer) return;
    if (typeof EventSource === 'undefined') { startPolling(); return; }
    stream = new EventSource('/api/scan/stream?since=' + logSinceIndex);
    stream.onmessage = function (evt) {
        const data = JSON.parse(evt.data);
        appendLogLines(data.log_lines);
        logSinceIndex = data.log_total;
        updateStatus(data.state);
    };
    stream.onerror = function () {
        stream.close();
        stream = null;
        startPolling();
    };
}

function collectPayload() {
    const payload = {
        mode: currentMode,
        target: $('target').value.trim(),
        operator: $('operator').value.trim(),
        ot_mode: $('otMode').checked,
        demo_mode: $('demoMode').checked,
        max_workers: $('maxWorkers').value,
    };
    if (currentMode === 'NETWORK_SCAN') {
        payload.port_mode = $('portMode').value;
        payload.custom_ports = $('customPorts').value.trim();
    } else {
        payload.username = $('username').value.trim();
        payload.password = $('password').value;
        payload.connect_timeout = $('connectTimeout').value;
        payload.device_type = $('deviceType').value;
        if (payload.device_type === 'configfile') payload.config_text = $('configText').value;
        payload.db_username = $('dbUsername').value.trim();
        payload.db_password = $('dbPassword').value;
        payload.oracle_service = $('oracleService').value.trim();
    }
    return payload;
}

$('btnStart').addEventListener('click', function () {
    const payload = collectPayload();
    if (!payload.target) { alert('대상을 입력하세요.'); return; }
    if (currentMode === 'NETWORK_SCAN' && payload.port_mode === 'full') {
        if (!confirm('전체 포트(1-65535) 스캔은 시간이 매우 오래 걸리고 네트워크 부하가 발생할 수 있습니다.\n계속하시겠습니까?')) return;
    }

    zvsRequestNotify(); // 스캔 종료 알림 권한 - 클릭(사용자 제스처) 시점이어야 브라우저가 요청을 띄워준다
    $('btnStart').disabled = true;
    zvsFetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    })
        .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
        .then(function (r) {
            if (r.status !== 200) {
                alert(r.body.error || '스캔 시작 실패');
                $('btnStart').disabled = false;
                return;
            }
            logSinceIndex = 0;
            $('logConsole').textContent = '';
            startStream();
        })
        .catch(function (err) {
            alert('요청 실패: ' + err);
            $('btnStart').disabled = false;
        });
});

$('btnStop').addEventListener('click', function () {
    zvsFetch('/api/scan/stop', { method: 'POST' }).catch(function () {});
});

document.querySelectorAll('.report-buttons button').forEach(function (btn) {
    btn.addEventListener('click', function () {
        const type = btn.getAttribute('data-report');
        const resultBox = $('reportResult');
        resultBox.textContent = '생성 중...';
        btn.disabled = true;
        zvsFetch('/api/reports/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: type }),
        })
            .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
            .then(function (r) {
                btn.disabled = false;
                if (r.status !== 200) {
                    resultBox.textContent = r.body.error || '리포트 생성 실패';
                    return;
                }
                resultBox.innerHTML = '생성 완료: <a href="' + r.body.download_url + '">' + r.body.filename + ' 다운로드</a>';
                loadReportList();
            })
            .catch(function (err) {
                btn.disabled = false;
                resultBox.textContent = '요청 실패: ' + err;
            });
    });
});

function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

function formatBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / (1024 * 1024)).toFixed(1) + ' MB';
}

function loadReportList() {
    fetch('/api/reports/list')
        .then(function (res) { return res.status === 200 ? res.json() : []; })
        .then(function (files) {
            const tbody = $('reportListBody');
            tbody.innerHTML = '';
            $('reportListEmpty').style.display = files.length ? 'none' : 'block';
            files.forEach(function (f) {
                const tr = document.createElement('tr');
                tr.innerHTML =
                    '<td><a href="' + f.download_url + '">' + esc(f.filename) + '</a></td>' +
                    '<td>' + formatBytes(f.size_bytes) + '</td>' +
                    '<td>' + esc(f.modified_at) + '</td>';
                tbody.appendChild(tr);
            });
        })
        .catch(function () {});
}

$('btnRefreshReports').addEventListener('click', loadReportList);
loadReportList();

// [권한 분리 - UX] 실제 차단은 서버(_operator_required)가 하지만, 조회자(viewer)
// 계정에게 눌러도 403만 돌아오는 버튼을 그대로 보여주는 건 혼란스러우므로 미리
// 비활성화하고 안내를 띄운다.
document.addEventListener('zvs:ready', function (evt) {
    if (evt.detail.role !== 'viewer') return;
    ['btnStart', 'btnStop'].forEach(function (id) { $(id).disabled = true; });
    document.querySelectorAll('.report-buttons button').forEach(function (btn) { btn.disabled = true; });
    const notice = document.createElement('p');
    notice.style.cssText = 'font-size:12px;color:var(--warning-text,#8A6A00);background:var(--warning-bg,#FFF6D6);padding:8px 12px;border-radius:8px;';
    notice.textContent = '조회 전용 계정입니다 - 스캔 실행/리포트 생성은 운영자 이상 권한이 필요합니다.';
    document.querySelector('.wrap').insertBefore(notice, document.querySelector('.wrap').firstChild);
});

// 페이지 진입 시 이미 실행 중인 스캔이 있으면(다른 탭/새로고침 후 복귀) 바로 이어서 폴링
startStream();

(function () {
    const sel = document.getElementById('deviceType');
    const box = document.getElementById('configFileBox');
    const file = document.getElementById('configFile');
    if (!sel || !box) return;
    sel.addEventListener('change', function () {
        box.classList.toggle('hidden', sel.value !== 'configfile');
    });
    file.addEventListener('change', function () {
        const f = file.files && file.files[0];
        if (!f) return;
        if (f.size > 2 * 1024 * 1024) { alert('설정 파일이 너무 큽니다(최대 2MB).'); file.value = ''; return; }
        const reader = new FileReader();
        reader.onload = function () { document.getElementById('configText').value = reader.result; };
        reader.readAsText(f);
    });
})();
