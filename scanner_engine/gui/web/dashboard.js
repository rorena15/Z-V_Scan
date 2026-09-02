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
