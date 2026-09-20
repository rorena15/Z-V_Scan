/*
Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
This software is proprietary and confidential.
Unauthorized copying, modification, distribution, or reverse engineering
of this file, via any medium, is strictly prohibited.

[UI/UX 개선 - "보고서형" 대시보드, 2026-09] main_window.py의 refresh_insights_charts()가
`page().runJavaScript()`로 이 페이지에 데이터를 직접 밀어넣으면(window.renderFromPython)
그걸 받아 Chart.js로 그린다. Python -> JS는 이렇게 단방향 push면 충분하지만,
JS -> Python(차트/랭킹 클릭 시 "자산 탭으로 이동해줘")은 QWebChannel 대신
`zvulnscan://drill?...` 커스텀 스킴 네비게이션으로 처리한다(navigateToAssets() 참고) -
QWebChannel은 file:// 페이지에서 `qt.webChannelTransport`가 정의되지 않는 문제가
실측으로 확인됐다(Uncaught ReferenceError). 서버/네트워크 호출은 전혀 없다 - 전부
같은 프로세스 안의 runJavaScript()/커스텀 스킴 가로채기일 뿐이다.

["정보가 너무 부족하다" 피드백 반영] Python은 집계된 숫자가 아니라 최신 회차
findings 원본 배열 하나만 넘긴다(get_latest_findings()) - 위험도 분포/카테고리별
집계/Top 취약자산/Top 다발항목을 전부 이 파일이 그 원본에서 계산한다.

[탭 역할 재분리] 처음엔 클릭 시 이 페이지 안에 드릴다운 상세 테이블이 떴는데,
"대시보드는 한눈에 보는 현황만, 조치 가능한 상세 목록은 자산 탭에" 원칙에 맞춰
그 상세 테이블 자체를 자산 탭(main_window.py.drill_down_dashboard_filter())으로
옮겼다 - 여기서는 navigateToAssets()로 화면 전환만 요청한다.
*/
let charts = {};
let theme = null;
let allFindings = [];

const STATUS_ORDER = ['VULNERABLE', 'PARTIAL', 'SAFE', 'MANUAL', 'NA', 'ERROR'];

function renderFromPython(data) {
    if (data.error) {
        console.error('[Z-VulnScan] dashboard data error:', data.error);
        return;
    }
    theme = {
        colors: data.colors,
        status_colors: data.status_colors,
        status_labels: data.status_labels,
    };
    allFindings = data.findings || [];
    applyTheme(theme.colors);

    renderDonut();
    renderBar();
    renderTrend(data.security_history);
    renderTopHosts();
    renderTopCodes();
    if (document.body.classList.contains('web-mode')) renderWebExtras(data);
}

function applyTheme(colors) {
    const root = document.documentElement.style;
    root.setProperty('--surface-2', colors.surface_2);
    root.setProperty('--border', colors.border);
    root.setProperty('--text', colors.text);
    root.setProperty('--text-secondary', colors.text_secondary);
    root.setProperty('--text-muted', colors.text_muted);
    root.setProperty('--accent', colors.accent);
    root.setProperty('--accent-bg', colors.accent_bg);
    root.setProperty('--danger-text', colors.danger_text);
    root.setProperty('--danger-bg', colors.danger_bg);
    root.setProperty('--warning-text', colors.warning_text);
    root.setProperty('--warning-bg', colors.warning_bg);
}

function showEmpty(cardId, text) {
    const card = document.getElementById(cardId);
    const wrap = card.querySelector('.chart-wrap');
    if (wrap) wrap.style.display = 'none';
    const empty = card.querySelector('.empty-state');
    if (text) empty.textContent = text;
    empty.style.display = 'flex';
}

function hideEmpty(cardId) {
    const card = document.getElementById(cardId);
    const wrap = card.querySelector('.chart-wrap');
    if (wrap) wrap.style.display = 'block';
    card.querySelector('.empty-state').style.display = 'none';
}

// ------------------------------------------------------------------
// [탭 전환 요청] main_window.py._DashboardNavPage.javaScriptConsoleMessage()가
// 이 콘솔 메시지를 가로채 drill_down_dashboard_filter()를 호출, 자산 탭으로
// 전환 + 필터링한다. value2는 'host' 타입일 때만 쓰는 IP.
//
// [버그 수정 - 시행착오] 처음엔 `zvulnscan://` 커스텀 스킴으로 페이지 이동을
// 시도했는데(Qt 공식 문서가 권장하는 acceptNavigationRequest 가로채기 패턴),
// 개발 중 테스트 환경에서 반응이 들쭉날쭉해서 못 믿을 방식이었다 - console.log
// 가로채기가 스킴 등록도, 사용자 제스처도 필요 없이 훨씬 단순하고 실측으로
// 안정적임이 확인돼 이걸로 바꿨다.
// ------------------------------------------------------------------
function navigateToAssets(type, value, label, value2) {
    const payload = { type: type, value: value, label: label };
    if (value2 !== undefined) payload.value2 = value2;
    // [웹 대시보드 모드] 브라우저에는 console 가로채기를 받는 Qt가 없어 예전엔 클릭해도 아무 일도 없었다 -
    // http(s)로 열린 경우엔 자산 페이지(/assets)로 직접 이동하고, 필터는 쿼리스트링으로 넘긴다.
    if (location.protocol === 'http:' || location.protocol === 'https:') {
        const q = new URLSearchParams({ ftype: type, fvalue: value == null ? '' : value, flabel: label || '' });
        if (value2 !== undefined) q.set('fvalue2', value2);
        location.href = '/assets?' + q.toString();
        return;
    }
    console.log('ZVULNSCAN_NAV:' + JSON.stringify(payload));
}

// ------------------------------------------------------------------
// [위험도 분포] 도넛 - 클릭하면 그 status로 자산 탭 필터링
// ------------------------------------------------------------------
function renderDonut() {
    const labels = [], values = [], colors = [], keys = [];
    STATUS_ORDER.forEach(function (key) {
        const count = allFindings.filter(function (f) { return f.status === key; }).length;
        if (count === 0) return;
        labels.push(theme.status_labels[key] + ' (' + count + ')');
        values.push(count);
        colors.push(theme.status_colors[key]);
        keys.push(key);
    });

    if (charts.donut) { charts.donut.destroy(); charts.donut = null; }
    if (values.length === 0) { showEmpty('donutCard'); return; }
    hideEmpty('donutCard');

    charts.donut = new Chart(document.getElementById('donutChart'), {
        type: 'doughnut',
        data: { labels: labels, datasets: [{ data: values, backgroundColor: colors, borderColor: theme.colors.surface_2, borderWidth: 2 }] },
        options: {
            maintainAspectRatio: false,
            cutout: '55%',
            onClick: function (evt, elements) {
                if (!elements.length) return;
                const key = keys[elements[0].index];
                navigateToAssets('status', key, theme.status_labels[key] + ' 항목');
            },
            onHover: function (evt, elements) {
                evt.native.target.style.cursor = elements.length ? 'pointer' : 'default';
            },
            plugins: { legend: { position: 'bottom', labels: { color: theme.colors.text_secondary, font: { size: 11 }, boxWidth: 10 } } },
        },
    });
}

// ------------------------------------------------------------------
// [카테고리별 취약 현황] 가로 막대 - 클릭하면 그 카테고리로 자산 탭 필터링
// ------------------------------------------------------------------
function categoryBreakdown() {
    const tally = {};
    allFindings.forEach(function (f) {
        if (f.status !== 'VULNERABLE' && f.status !== 'PARTIAL') return;
        tally[f.category] = (tally[f.category] || 0) + 1;
    });
    return Object.keys(tally).map(function (k) { return [k, tally[k]]; })
        .sort(function (a, b) { return b[1] - a[1]; }).slice(0, 8);
}

function renderBar() {
    const breakdown = categoryBreakdown();
    if (charts.bar) { charts.bar.destroy(); charts.bar = null; }
    if (breakdown.length === 0) { showEmpty('barCard'); return; }
    hideEmpty('barCard');

    // 위쪽에 큰 값이 오도록 화면에 그릴 때만 뒤집는다
    const ordered = breakdown.slice().reverse();
    const labels = ordered.map(function (x) { return x[0]; });
    const values = ordered.map(function (x) { return x[1]; });

    charts.bar = new Chart(document.getElementById('barChart'), {
        type: 'bar',
        data: { labels: labels, datasets: [{ data: values, backgroundColor: theme.colors.danger_text, borderRadius: 4, barThickness: 16 }] },
        options: {
            indexAxis: 'y',
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            onClick: function (evt, elements) {
                if (!elements.length) return;
                const category = labels[elements[0].index];
                navigateToAssets('category', category, '"' + category + '" 카테고리 취약/부분만족');
            },
            onHover: function (evt, elements) {
                evt.native.target.style.cursor = elements.length ? 'pointer' : 'default';
            },
            scales: {
                x: { beginAtZero: true, ticks: { color: theme.colors.text_secondary, precision: 0 }, grid: { color: theme.colors.border } },
                y: { ticks: { color: theme.colors.text_secondary, font: { size: 11 } }, grid: { display: false } },
            },
        },
    });
}

function renderTrend(history) {
    if (charts.trend) { charts.trend.destroy(); charts.trend = null; }
    const points = (history || []).filter(function (h) { return h.security_level !== null; });
    if (points.length < 2) { showEmpty('trendCard'); return; }
    hideEmpty('trendCard');

    charts.trend = new Chart(document.getElementById('trendChart'), {
        type: 'line',
        data: {
            labels: points.map(function (p) { return p.round + '회차'; }),
            datasets: [{
                data: points.map(function (p) { return p.security_level; }),
                borderColor: theme.colors.accent,
                backgroundColor: theme.colors.accent_bg,
                fill: true,
                tension: 0.3,
                pointRadius: 3,
                pointBackgroundColor: theme.colors.accent,
            }],
        },
        options: {
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { min: 0, max: 100, ticks: { color: theme.colors.text_secondary }, grid: { color: theme.colors.border } },
                x: { ticks: { color: theme.colors.text_secondary }, grid: { display: false } },
            },
        },
    });
}

// ------------------------------------------------------------------
// [취약 자산 Top 10] 호스트별 취약/부분만족 건수 랭킹 - 행 클릭 시 그 호스트의
// 전체 findings(양호 포함)로 자산 탭 필터링 - "이 자산은 전체적으로 어떤 상태인지" 확인 목적
// ------------------------------------------------------------------
function topHosts() {
    const byHost = {};
    allFindings.forEach(function (f) {
        const key = f.hostname + '|' + f.ip;
        if (!byHost[key]) byHost[key] = { hostname: f.hostname, ip: f.ip, vuln: 0, partial: 0 };
        if (f.status === 'VULNERABLE') byHost[key].vuln += 1;
        else if (f.status === 'PARTIAL') byHost[key].partial += 1;
    });
    return Object.values(byHost)
        .filter(function (h) { return h.vuln + h.partial > 0; })
        .sort(function (a, b) { return (b.vuln * 2 + b.partial) - (a.vuln * 2 + a.partial); })
        .slice(0, 10);
}

function renderTopHosts() {
    const hosts = topHosts();
    const tbody = document.getElementById('topHostsBody');
    tbody.innerHTML = '';
    document.getElementById('topHostsEmpty').style.display = hosts.length === 0 ? 'flex' : 'none';
    document.querySelector('#topHostsCard .rank-list-wrap').style.display = hosts.length === 0 ? 'none' : 'block';

    hosts.forEach(function (h, i) {
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.innerHTML = '<td>' + (i + 1) + '</td><td>' + escapeHtml(h.hostname) + ' (' + escapeHtml(h.ip) + ')</td>' +
            '<td class="num">' + h.vuln + '</td><td class="num">' + h.partial + '</td>';
        tr.addEventListener('click', function () {
            navigateToAssets('host', h.hostname, h.hostname + ' (' + h.ip + ') 전체 항목', h.ip);
        });
        tbody.appendChild(tr);
    });
}

// ------------------------------------------------------------------
// [다발 취약 항목 Top 10] KISA 코드별로 몇 개 자산에서 취약/부분만족이 나왔는지 -
// 행 클릭 시 그 코드로 자산 탭 필터링
// ------------------------------------------------------------------
function topCodes() {
    const byCode = {};
    allFindings.forEach(function (f) {
        if (f.status !== 'VULNERABLE' && f.status !== 'PARTIAL') return;
        if (!byCode[f.code]) byCode[f.code] = { code: f.code, name: f.name, importance: f.importance, count: 0 };
        byCode[f.code].count += 1;
    });
    return Object.values(byCode).sort(function (a, b) { return b.count - a.count; }).slice(0, 10);
}

function importanceBadgeClass(importance) {
    if (importance === '상') return '';
    if (importance === '중') return 'mid';
    return 'low';
}

function renderTopCodes() {
    const codes = topCodes();
    const tbody = document.getElementById('topCodesBody');
    tbody.innerHTML = '';
    document.getElementById('topCodesEmpty').style.display = codes.length === 0 ? 'flex' : 'none';
    document.querySelector('#topCodesCard .rank-list-wrap').style.display = codes.length === 0 ? 'none' : 'block';

    codes.forEach(function (c, i) {
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.innerHTML = '<td>' + (i + 1) + '</td><td>' + escapeHtml(c.code) + '</td><td>' + escapeHtml(c.name) + '</td>' +
            '<td><span class="badge-importance ' + importanceBadgeClass(c.importance) + '">' + escapeHtml(c.importance) + '</span></td>' +
            '<td class="num">' + c.count + '</td>';
        tr.addEventListener('click', function () {
            navigateToAssets('code', c.code, '"' + c.code + ' ' + c.name + '" 발견 자산');
        });
        tbody.appendChild(tr);
    });
}

function escapeHtml(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

window.renderFromPython = renderFromPython;

// ------------------------------------------------------------------
// [웹 대시보드 모드] Qt(QWebEngineView, file://)에서는 main_window.py가
// runJavaScript()로 renderFromPython()을 직접 호출해서 이 블록이 필요 없다.
// web_dashboard_server.py가 http(s)://로 띄운 독립 브라우저 탭에서는 그런 푸시가
// 없으므로, 페이지 프로토콜이 http(s)일 때만 /api/dashboard-data를 직접 불러와
// 같은 함수를 호출한다 - 렌더링 로직은 완전히 동일하게 재사용.
// ------------------------------------------------------------------
if (location.protocol === 'http:' || location.protocol === 'https:') {
    // topbar.js(개인 테마 팔레트 포함)를 먼저 불러온 뒤에 데이터를 그려야, 개인
    // 다크/라이트 선택이 Chart.js 색에도 반영된다.
    loadWebTopbar(function () {
        // Qt 임베드에서는 body가 투명(앱 배경을 그대로 씀)인데, 브라우저 단독 탭에선
        // 개인 다크모드가 보이려면 페이지 자체 배경이 필요하다.
        document.body.style.background = 'var(--surface-1, #F5F7FA)';
        document.body.classList.add('web-mode');
        fetch('/api/dashboard-data')
            .then(function (res) {
                if (res.status === 401) { location.href = '/login'; return null; }
                return res.json();
            })
            .then(function (data) {
                if (!data) return;
                const personal = (typeof zvsThemeColors === 'function') ? zvsThemeColors() : null;
                if (personal) data.colors = Object.assign({}, data.colors, personal);
                renderFromPython(data);
            })
            .catch(function (err) { console.error('[Z-VulnScan] dashboard fetch failed:', err); });
    });
}

// ------------------------------------------------------------------
// [웹 전용 확장 블록, 2026-09] "웹 대시보드가 너무 휑하다"는 피드백으로 KPI 타일, 중요도/OS 분포, 스캔 상태,
// 자산별 요약, 회차별 변화, 최근 리포트를 채웠다. Qt 내장 대시보드에서는 실행되지 않는다(web-mode 클래스 없음).
// 모든 집계는 이미 받은 findings 원본에서 계산하고, 그 밖의 데이터는 기존 API를 그대로 쓴다.
// ------------------------------------------------------------------
const OS_PALETTE = ['#5B8DEF', '#3ECB7A', '#F0C24D', '#FF6B5C', '#9B7BEF', '#4FC3D9', '#8B94A3'];

function escHtml(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function statusCount(status) {
    return allFindings.filter(function (f) { return f.status === status; }).length;
}

function renderKpi(data) {
    const hosts = new Set(allFindings.map(function (f) { return f.ip; })).size;
    const total = allFindings.length;
    const vuln = statusCount('VULNERABLE'), partial = statusCount('PARTIAL'), safe = statusCount('SAFE');
    const pct = function (n) { return total ? Math.round(n * 100 / total) + '%' : '-'; };
    const hist = (data.security_history || []).filter(function (h) { return h.security_level != null; });
    const score = hist.length ? hist[hist.length - 1].security_level : null;
    const tiles = [
        { label: '점검 자산', value: hosts, sub: '최신 회차 기준' },
        { label: '점검 항목', value: total, sub: '예외처리 제외' },
        { label: '취약', value: vuln, sub: '전체의 ' + pct(vuln), color: theme.status_colors.VULNERABLE, status: 'VULNERABLE' },
        { label: '부분만족', value: partial, sub: '전체의 ' + pct(partial), color: theme.status_colors.PARTIAL, status: 'PARTIAL' },
        { label: '양호', value: safe, sub: '전체의 ' + pct(safe), color: theme.status_colors.SAFE, status: 'SAFE' },
        { label: '보안수준', value: score == null ? '-' : Math.round(score) + '점', sub: hist.length > 1 ? '직전 회차 ' + Math.round(hist[hist.length - 2].security_level) + '점' : '최신 회차' },
    ];
    const row = document.getElementById('kpiRow');
    row.innerHTML = '';
    tiles.forEach(function (t) {
        const el = document.createElement('div');
        el.className = 'card kpi' + (t.status ? ' clickable' : '');
        el.innerHTML = '<div class="kpi-label">' + escHtml(t.label) + '</div>' +
            '<div class="kpi-value"' + (t.color ? ' style="color:' + t.color + ';"' : '') + '>' + escHtml(t.value) + '</div>' +
            '<div class="kpi-sub">' + escHtml(t.sub) + '</div>';
        if (t.status) el.addEventListener('click', function () { navigateToAssets('status', t.status, theme.status_labels[t.status] + ' 항목'); });
        row.appendChild(el);
    });
}

function renderImportance() {
    const groups = ['상', '중', '하'];
    const count = function (imp, st) {
        return allFindings.filter(function (f) { return f.importance === imp && f.status === st; }).length;
    };
    const vuln = groups.map(function (g) { return count(g, 'VULNERABLE'); });
    const part = groups.map(function (g) { return count(g, 'PARTIAL'); });
    if (vuln.concat(part).every(function (n) { return n === 0; })) { showEmpty('importanceCard'); return; }
    hideEmpty('importanceCard');
    if (charts.importance) charts.importance.destroy();
    const text = getComputedStyle(document.documentElement).getPropertyValue('--text-secondary') || '#5B6675';
    charts.importance = new Chart(document.getElementById('importanceChart'), {
        type: 'bar',
        data: { labels: ['중요도 상', '중요도 중', '중요도 하'], datasets: [
            { label: '취약', data: vuln, backgroundColor: theme.status_colors.VULNERABLE, borderRadius: 4 },
            { label: '부분만족', data: part, backgroundColor: theme.status_colors.PARTIAL, borderRadius: 4 },
        ] },
        options: {
            responsive: true, maintainAspectRatio: false,
            scales: { x: { stacked: true, ticks: { color: text } }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0, color: text } } },
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, color: text } } },
        },
    });
}

function renderOsChart() {
    const byIp = {};
    allFindings.forEach(function (f) { byIp[f.ip] = f.os_type || '알 수 없음'; });
    const counts = {};
    Object.keys(byIp).forEach(function (ip) { counts[byIp[ip]] = (counts[byIp[ip]] || 0) + 1; });
    const labels = Object.keys(counts);
    if (!labels.length) { showEmpty('osCard'); return; }
    hideEmpty('osCard');
    if (charts.os) charts.os.destroy();
    const text = getComputedStyle(document.documentElement).getPropertyValue('--text-secondary') || '#5B6675';
    charts.os = new Chart(document.getElementById('osChart'), {
        type: 'doughnut',
        data: { labels: labels.map(function (l) { return l + ' (' + counts[l] + ')'; }),
                datasets: [{ data: labels.map(function (l) { return counts[l]; }),
                             backgroundColor: labels.map(function (_, i) { return OS_PALETTE[i % OS_PALETTE.length]; }), borderWidth: 1 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: '58%',
                   plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, color: text } } } },
    });
}

function renderHostSummary() {
    const hosts = {};
    allFindings.forEach(function (f) {
        const key = f.ip;
        const h = hosts[key] || (hosts[key] = { ip: f.ip, hostname: f.hostname, VULNERABLE: 0, PARTIAL: 0, SAFE: 0, other: 0, total: 0 });
        h.total += 1;
        if (f.status === 'VULNERABLE' || f.status === 'PARTIAL' || f.status === 'SAFE') h[f.status] += 1; else h.other += 1;
    });
    const list = Object.keys(hosts).map(function (k) { return hosts[k]; }).sort(function (a, b) {
        return (b.VULNERABLE - a.VULNERABLE) || (b.PARTIAL - a.PARTIAL) || (a.ip < b.ip ? -1 : 1);
    }).slice(0, 15);
    const tbody = document.getElementById('hostSummaryBody');
    tbody.innerHTML = '';
    document.getElementById('hostSummaryEmpty').style.display = list.length ? 'none' : 'flex';
    list.forEach(function (h) {
        const w = function (n) { return (n * 100 / h.total).toFixed(1) + '%'; };
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.innerHTML = '<td>' + escHtml(h.hostname) + ' <span style="color:var(--text-muted);">(' + escHtml(h.ip) + ')</span></td>' +
            '<td><div class="host-bar">' +
            '<span style="width:' + w(h.VULNERABLE) + ';background:' + theme.status_colors.VULNERABLE + ';"></span>' +
            '<span style="width:' + w(h.PARTIAL) + ';background:' + theme.status_colors.PARTIAL + ';"></span>' +
            '<span style="width:' + w(h.SAFE) + ';background:' + theme.status_colors.SAFE + ';"></span></div></td>' +
            '<td class="num">' + h.VULNERABLE + '</td><td class="num">' + h.PARTIAL + '</td><td class="num">' + h.SAFE + '</td>';
        tr.addEventListener('click', function () { navigateToAssets('host', h.hostname, h.hostname + ' (' + h.ip + ') 전체 항목', h.ip); });
        tbody.appendChild(tr);
    });
}

function loadScanState() {
    fetch('/api/scan/summary')
        .then(function (res) { return res.status === 200 ? res.json() : null; })
        .then(function (s) {
            const el = document.getElementById('scanStateBody');
            if (!s) { el.textContent = '상태를 불러오지 못했습니다.'; return; }
            if (s.running) {
                el.innerHTML = '<b>실행 중</b> - ' + escHtml(s.target || '') + '<div class="scan-bar"><span style="width:' + (s.percent || 0) + '%;"></span></div>' +
                    escHtml(s.percent || 0) + '% (' + escHtml(s.current || 0) + ' / ' + escHtml(s.total || 0) + ')';
            } else {
                el.innerHTML = '대기 중' + (s.finished_reason ? '<br><span style="color:var(--text-muted);font-size:12px;">마지막: ' +
                    escHtml(s.target || '') + ' - ' + escHtml(s.finished_reason) + '</span>' : '<br><span style="color:var(--text-muted);font-size:12px;">진행 중인 스캔이 없습니다.</span>');
            }
        })
        .catch(function () {});
}

function loadChanges() {
    fetch('/api/compare')
        .then(function (res) { return res.status === 200 ? res.json() : []; })
        .then(function (rows) {
            rows = (rows || []).filter(function (r) { return r.improvement != null; })
                .sort(function (a, b) { return Math.abs(b.improvement) - Math.abs(a.improvement); }).slice(0, 8);
            const tbody = document.getElementById('changeBody');
            tbody.innerHTML = '';
            document.getElementById('changeEmpty').style.display = rows.length ? 'none' : 'flex';
            rows.forEach(function (r) {
                const up = r.improvement >= 0;
                const tr = document.createElement('tr');
                tr.innerHTML = '<td>' + escHtml(r.hostname || r.ip) + '</td>' +
                    '<td class="num">' + escHtml(Math.round(r.prev_score)) + ' → ' + escHtml(Math.round(r.current_score)) + '</td>' +
                    '<td class="num ' + (up ? 'delta-up' : 'delta-down') + '">' + (up ? '▲ +' : '▼ ') + escHtml(Math.round(r.improvement)) + '</td>' +
                    '<td class="num">' + escHtml(r.prev_vuln_total) + ' → ' + escHtml(r.current_vuln_total) + '</td>';
                tbody.appendChild(tr);
            });
        })
        .catch(function () {});
}

function loadRecentReports() {
    fetch('/api/reports/list')
        .then(function (res) { return res.status === 200 ? res.json() : []; })
        .then(function (rows) {
            rows = (rows || []).slice(0, 5);
            const box = document.getElementById('reportsBody');
            box.innerHTML = rows.map(function (r) {
                return '<div><a href="' + escHtml(r.download_url) + '">' + escHtml(r.filename) + '</a>' +
                    '<span style="color:var(--text-muted);white-space:nowrap;">' + escHtml(r.modified_at) + ' · ' + Math.max(1, Math.round(r.size_bytes / 1024)) + 'KB</span></div>';
            }).join('');
            document.getElementById('reportsEmpty').style.display = rows.length ? 'none' : 'flex';
        })
        .catch(function () {});
}

function renderWebExtras(data) {
    renderKpi(data);
    renderImportance();
    renderOsChart();
    renderHostSummary();
    loadScanState();
    loadChanges();
    loadRecentReports();
    if (!window._zvsScanStateTimer) window._zvsScanStateTimer = setInterval(loadScanState, 5000);
}

// ------------------------------------------------------------------
// [웹 대시보드 모드 - 상단 네비게이션] 공용 topbar.js(gui/web/topbar.js)를 동적으로
// 불러와 zvsRenderTopbar()를 호출한다. Qt(QWebEngineView, file://) 쪽에서는 이
// 블록 자체가 실행되지 않으므로(위 protocol 가드), <script src="/topbar.js">를
// dashboard.html에 고정으로 넣어서 file://에서 404를 내는 대신 필요할 때만 동적으로
// 주입한다.
// ------------------------------------------------------------------
function loadWebTopbar(done) {
    const script = document.createElement('script');
    script.src = '/topbar.js';
    script.onload = function () { zvsRenderTopbar('dashboard'); done(); };
    script.onerror = function () { done(); };
    document.head.appendChild(script);
}
