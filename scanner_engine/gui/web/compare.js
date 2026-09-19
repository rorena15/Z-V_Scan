/*
Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
This software is proprietary and confidential.
Unauthorized copying, modification, distribution, or reverse engineering
of this file, via any medium, is strictly prohibited.
*/
zvsRenderTopbar('compare');

const STATUS_LABEL = { VULNERABLE: '취약', SAFE: '양호', PARTIAL: '부분만족', NA: '해당없음', MANUAL: '검토필요', ERROR: '점검불가' };
const DIRECTION_LABEL = { improved: '개선', worsened: '악화', changed: '변경' };

function $(id) { return document.getElementById(id); }
function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }

function deltaCell(d) {
    const cls = d > 0 ? 'up' : (d < 0 ? 'down' : 'flat');
    const sign = d > 0 ? '+' : '';
    return '<span class="delta ' + cls + '">' + sign + d + '</span>';
}

function loadCompare() {
    fetch('/api/compare')
        .then(function (res) {
            if (res.status === 401) { location.href = '/login'; return null; }
            return res.json();
        })
        .then(function (rows) {
            if (!rows) return;
            rows.sort(function (a, b) { return a.improvement - b.improvement; }); // 악화된 자산이 위로
            const tbody = $('compareBody');
            tbody.innerHTML = '';
            $('compareEmpty').style.display = rows.length ? 'none' : 'block';
            rows.forEach(function (r) {
                const tr = document.createElement('tr');
                tr.className = 'clickable';
                tr.innerHTML =
                    '<td>' + esc(r.hostname || r.ip) + ' <span style="color:var(--text-muted)">(' + esc(r.ip) + ')</span></td>' +
                    '<td>' + r.prev_score + '</td><td><strong>' + r.current_score + '</strong></td>' +
                    '<td><div class="bar"><div style="width:' + Math.max(0, Math.min(100, r.current_score)) + '%"></div></div></td>' +
                    '<td>' + deltaCell(r.improvement) + '</td>' +
                    '<td>' + r.prev_vuln_total + ' → ' + r.current_vuln_total + '</td>' +
                    '<td>' + r.prev_partial_total + ' → ' + r.current_partial_total + '</td>';
                tr.addEventListener('click', function () { loadDetail(r); });
                tbody.appendChild(tr);
            });
        });
}

function loadDetail(asset) {
    $('detailCard').style.display = 'block';
    $('detailTitle').textContent = '항목별 변화 - ' + (asset.hostname || asset.ip) + ' (' + asset.ip + ')';
    fetch('/api/compare/' + asset.asset_id)
        .then(function (res) { return res.json(); })
        .then(function (changes) {
            const tbody = $('detailBody');
            tbody.innerHTML = '';
            $('detailEmpty').style.display = changes.length ? 'none' : 'block';
            changes.forEach(function (c) {
                const tr = document.createElement('tr');
                tr.innerHTML =
                    '<td>' + esc(c.code) + '</td><td>' + esc(c.name) + '</td>' +
                    '<td>' + esc(STATUS_LABEL[c.prev_status] || c.prev_status) + '</td>' +
                    '<td>' + esc(STATUS_LABEL[c.current_status] || c.current_status) + '</td>' +
                    '<td><span class="badge ' + esc(c.direction) + '">' + esc(DIRECTION_LABEL[c.direction] || c.direction) + '</span></td>';
                tbody.appendChild(tr);
            });
            $('detailCard').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        });
}

loadCompare();
