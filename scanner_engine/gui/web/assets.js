/*
Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
This software is proprietary and confidential.
Unauthorized copying, modification, distribution, or reverse engineering
of this file, via any medium, is strictly prohibited.
*/
zvsRenderTopbar('assets');

let allAssets = [];
let currentAssetId = null;

const STATUS_LABEL = { VULNERABLE: '취약', SAFE: '양호', PARTIAL: '부분만족', NA: '해당없음', MANUAL: '검토필요', ERROR: '점검불가' };
const EDITABLE_FIELDS = ['hostname', 'os_type', 'mac_addr', 'description', 'zone_tag'];

function $(id) { return document.getElementById(id); }
function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

function loadAssets() {
    fetch('/api/assets')
        .then(function (res) {
            if (res.status === 401) { location.href = '/login'; return null; }
            return res.json();
        })
        .then(function (data) {
            if (!data) return;
            allAssets = data;
            populateZoneFilter();
            renderAssets();
            applyDrillFilter();
        });
}

// ------------------------------------------------------------------
// [대시보드 -> 자산 탭 보기] 대시보드의 차트/랭킹을 클릭하면 /assets?ftype=...&fvalue=...로 넘어온다
// (dashboard.js navigateToAssets). Qt의 main_window.drill_down_dashboard_filter()와 같은 기준으로
// 최신 회차 findings를 걸러 자산 목록 위에 보여준다. 주소창의 쿼리를 지우면(필터 해제) 원래 화면이다.
// ------------------------------------------------------------------
const DRILL = (function () {
    const q = new URLSearchParams(location.search);
    return q.has('ftype') ? { type: q.get('ftype'), value: q.get('fvalue') || '', label: q.get('flabel') || '', value2: q.get('fvalue2') || '' } : null;
})();
let drillRendered = false;

function drillFilter(findings) {
    if (DRILL.type === 'status') return findings.filter(function (f) { return f.status === DRILL.value; });
    if (DRILL.type === 'category') return findings.filter(function (f) { return f.category === DRILL.value && (f.status === 'VULNERABLE' || f.status === 'PARTIAL'); });
    if (DRILL.type === 'host') return findings.filter(function (f) { return f.hostname === DRILL.value && f.ip === DRILL.value2; });
    if (DRILL.type === 'code') return findings.filter(function (f) { return f.code === DRILL.value && (f.status === 'VULNERABLE' || f.status === 'PARTIAL'); });
    return findings;
}

function applyDrillFilter() {
    if (!DRILL || drillRendered) return;
    drillRendered = true;
    fetch('/api/dashboard-data')
        .then(function (res) { return res.status === 200 ? res.json() : null; })
        .then(function (data) {
            if (!data) return;
            const rows = drillFilter(data.findings || []);
            $('filterCard').style.display = 'block';
            $('filterTitle').textContent = (DRILL.label || '필터 결과') + ' (' + rows.length + '건)';
            $('filterEmpty').style.display = rows.length ? 'none' : 'block';
            const tbody = $('filterBody');
            tbody.innerHTML = '';
            rows.forEach(function (f) {
                const asset = allAssets.find(function (a) { return a.ip === f.ip; });
                const tr = document.createElement('tr');
                tr.innerHTML =
                    '<td>' + esc(f.hostname) + '</td><td>' + esc(f.ip) + '</td><td>' + esc(f.code) + '</td><td>' + esc(f.name) + '</td>' +
                    '<td>' + esc(f.importance) + '</td>' +
                    '<td><span class="badge ' + esc(f.status) + '">' + esc(STATUS_LABEL[f.status] || f.status) + '</span></td>' +
                    '<td>' + esc(f.risk) + '</td>' +
                    '<td>' + (asset ? '<button class="btn btn-secondary rowbtn" data-fview="' + asset.id + '">점검 결과</button>' : '') + '</td>';
                tbody.appendChild(tr);
            });
            tbody.querySelectorAll('[data-fview]').forEach(function (btn) {
                btn.addEventListener('click', function () { showResults(btn.getAttribute('data-fview')); });
            });
            $('filterCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
        })
        .catch(function () {});
}

$('btnClearFilter').addEventListener('click', function () { location.href = '/assets'; });

function populateZoneFilter() {
    const sel = $('zoneFilter');
    const current = sel.value;
    const zones = Array.from(new Set(allAssets.map(function (a) { return a.zone_tag; }).filter(Boolean))).sort();
    sel.innerHTML = '<option value="">전체 구역</option>' + zones.map(function (z) {
        return '<option value="' + esc(z) + '">' + esc(z) + '</option>';
    }).join('');
    if (zones.indexOf(current) >= 0) sel.value = current;
}

function canWrite() {
    // [권한 분리 - UX] 서버(_operator_required)가 실제 차단선이고, 이건 조회자
    // (viewer)에게 눌러봤자 403만 나는 컨트롤을 아예 편집 가능한 것처럼 보여주지
    // 않기 위한 화면단 배려일 뿐이다. window.ZVS_ROLE은 topbar.js의 zvs:ready
    // 이벤트가 채워준다(비어있으면 아직 확인 전이라 일단 편집 가능한 것으로
    // 취급 - loadAssets()를 zvs:ready 이후에만 호출하므로 실제로는 항상 채워져 있다).
    return window.ZVS_ROLE !== 'viewer';
}

function renderAssets() {
    const filter = $('zoneFilter').value;
    const rows = filter ? allAssets.filter(function (a) { return a.zone_tag === filter; }) : allAssets;
    const tbody = $('assetsBody');
    tbody.innerHTML = '';
    $('assetsEmpty').style.display = rows.length ? 'none' : 'block';

    const editable = canWrite();
    const editAttr = editable ? ' contenteditable="true"' : '';
    const checkboxAttr = editable ? '' : ' disabled';

    rows.forEach(function (a) {
        const tr = document.createElement('tr');
        tr.dataset.id = a.id;
        tr.innerHTML =
            '<td><input type="checkbox" class="rowcheck" data-id="' + a.id + '"' + checkboxAttr + '></td>' +
            '<td>' + esc(a.ip) + '</td>' +
            '<td' + editAttr + ' data-field="hostname">' + esc(a.hostname) + '</td>' +
            '<td' + editAttr + ' data-field="os_type">' + esc(a.os_type) + '</td>' +
            '<td' + editAttr + ' data-field="mac_addr">' + esc(a.mac_addr) + '</td>' +
            '<td>' + esc(a.open_ports) + '</td>' +
            '<td>' + esc(a.last_seen) + '</td>' +
            '<td' + editAttr + ' data-field="description">' + esc(a.description) + '</td>' +
            '<td' + editAttr + ' data-field="zone_tag">' + esc(a.zone_tag) + '</td>' +
            '<td><button class="btn btn-secondary rowbtn" data-view="' + a.id + '">점검 결과</button></td>';
        tbody.appendChild(tr);
    });

    tbody.querySelectorAll('td[contenteditable="true"]').forEach(function (cell) {
        const original = cell.textContent;
        cell.dataset.original = original;
        cell.addEventListener('blur', function () { onCellBlur(cell); });
        cell.addEventListener('keydown', function (evt) {
            if (evt.key === 'Enter') { evt.preventDefault(); cell.blur(); }
        });
    });
    tbody.querySelectorAll('[data-view]').forEach(function (btn) {
        btn.addEventListener('click', function () { showResults(btn.getAttribute('data-view')); });
    });

    $('btnDeleteSelected').disabled = !editable;
    $('checkAll').disabled = !editable;
}

function onCellBlur(cell) {
    const newValue = cell.textContent.trim();
    if (newValue === cell.dataset.original) return;
    const tr = cell.closest('tr');
    const assetId = tr.dataset.id;
    const field = cell.dataset.field;
    zvsFetch('/api/assets/' + assetId, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ field: field, value: newValue }),
    })
        .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
        .then(function (r) {
            if (r.status !== 200) {
                alert(r.body.error || '수정 실패');
                cell.textContent = cell.dataset.original;
            } else {
                cell.dataset.original = newValue;
                const asset = allAssets.find(function (a) { return String(a.id) === String(assetId); });
                if (asset) asset[field] = newValue;
            }
        })
        .catch(function () { cell.textContent = cell.dataset.original; });
}

$('checkAll').addEventListener('change', function () {
    document.querySelectorAll('.rowcheck').forEach(function (cb) { cb.checked = $('checkAll').checked; });
});

$('btnRefresh').addEventListener('click', loadAssets);
$('zoneFilter').addEventListener('change', renderAssets);

$('btnDeleteSelected').addEventListener('click', function () {
    const ids = Array.from(document.querySelectorAll('.rowcheck:checked')).map(function (cb) { return cb.getAttribute('data-id'); });
    if (!ids.length) { alert('삭제할 자산을 선택하세요.'); return; }
    if (!confirm(ids.length + '개 자산을 삭제합니다. 관련된 모든 스캔 기록도 함께 영구 삭제됩니다.\n계속하시겠습니까?')) return;

    Promise.all(ids.map(function (id) {
        return zvsFetch('/api/assets/' + id, { method: 'DELETE' }).then(function (res) { return res.ok; });
    })).then(function (results) {
        const failCount = results.filter(function (ok) { return !ok; }).length;
        if (failCount) alert(failCount + '개 삭제에 실패했습니다.');
        loadAssets();
    });
});

function showResults(assetId) {
    currentAssetId = assetId;
    const asset = allAssets.find(function (a) { return String(a.id) === String(assetId); });
    $('resultsCard').style.display = 'block';
    $('resultsTitle').textContent = '점검 결과 - ' + (asset ? (asset.hostname || asset.ip) + ' (' + asset.ip + ')' : assetId);
    $('resultsCard').scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    fetch('/api/assets/' + assetId + '/results')
        .then(function (res) { return res.json(); })
        .then(renderResults)
        .catch(function () {});
}

function renderResults(results) {
    const tbody = $('resultsBody');
    tbody.innerHTML = '';
    $('resultsEmpty').style.display = results.length ? 'none' : 'block';

    const editable = canWrite();
    results.forEach(function (r) {
        const tr = document.createElement('tr');
        const displayCode = r.kisa_code || r.code;
        const waivedLabel = r.waived ? ('예외처리됨 (' + esc(r.approver || '') + ', ' + esc(r.waiver_date || '') + ')') : '-';
        const actionBtn = !editable ? '' : (r.waived
            ? '<button class="btn btn-secondary rowbtn" data-unwaive="' + r.result_id + '">예외 해제</button>'
            : '<button class="btn btn-secondary rowbtn" data-waive="' + r.result_id + '" data-label="' + esc(displayCode + ' - ' + (r.name || '')) + '">예외처리</button>');
        tr.innerHTML =
            '<td>' + esc(displayCode) + '</td>' +
            '<td>' + esc(r.name) + '</td>' +
            '<td>' + esc(r.risk) + '</td>' +
            '<td><span class="badge ' + esc(r.status) + '">' + esc(STATUS_LABEL[r.status] || r.status) + '</span></td>' +
            '<td>' + waivedLabel + '</td>' +
            '<td>' + actionBtn + '</td>';
        tbody.appendChild(tr);
    });

    tbody.querySelectorAll('[data-waive]').forEach(function (btn) {
        btn.addEventListener('click', function () { waiveResult(btn.getAttribute('data-waive'), btn.getAttribute('data-label')); });
    });
    tbody.querySelectorAll('[data-unwaive]').forEach(function (btn) {
        btn.addEventListener('click', function () { unwaiveResult(btn.getAttribute('data-unwaive')); });
    });
}

function waiveResult(resultId, label) {
    const reason = prompt('예외처리 사유를 입력하세요 (' + label + '):');
    if (reason === null) return;
    if (!reason.trim()) { alert('사유는 필수입니다.'); return; }
    const approver = prompt('승인자를 입력하세요:');
    if (approver === null) return;
    if (!approver.trim()) { alert('승인자는 필수입니다.'); return; }

    zvsFetch('/api/assets/' + currentAssetId + '/waiver', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ result_id: resultId, waived: true, reason: reason.trim(), approver: approver.trim() }),
    })
        .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
        .then(function (r) {
            if (r.status !== 200) { alert(r.body.error || '예외처리 실패'); return; }
            showResults(currentAssetId);
        });
}

function unwaiveResult(resultId) {
    if (!confirm('선택한 항목의 예외처리를 해제하시겠습니까?')) return;
    zvsFetch('/api/assets/' + currentAssetId + '/waiver', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ result_id: resultId, waived: false }),
    })
        .then(function (res) { return res.json().then(function (body) { return { status: res.status, body: body }; }); })
        .then(function (r) {
            if (r.status !== 200) { alert(r.body.error || '예외 해제 실패'); return; }
            showResults(currentAssetId);
        });
}

// [초기 렌더 전 role 확정] loadAssets()가 zvs:ready(topbar.js가 /api/whoami
// 확인 후 쏘는 이벤트)보다 먼저 실행되면 window.ZVS_ROLE이 아직 없어 조회자에게도
// 편집 가능한 셀이 잠깐 보일 수 있다 - 그 레이스를 없애기 위해 로딩을 이 이벤트
// 이후로 미룬다.
document.addEventListener('zvs:ready', function (evt) {
    if (evt.detail.role === 'viewer') {
        const notice = document.createElement('p');
        notice.style.cssText = 'font-size:12px;color:var(--warning-text,#8A6A00);background:var(--warning-bg,#FFF6D6);padding:8px 12px;border-radius:8px;';
        notice.textContent = '조회 전용 계정입니다 - 자산 편집/삭제/예외처리는 운영자 이상 권한이 필요합니다.';
        document.querySelector('.wrap').insertBefore(notice, document.querySelector('.wrap').firstChild);
    }
    loadAssets();
});
