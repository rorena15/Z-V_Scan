/*
Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
This software is proprietary and confidential.
Unauthorized copying, modification, distribution, or reverse engineering
of this file, via any medium, is strictly prohibited.

[공용 상단 네비게이션] 페이지가 늘어나면서 각 HTML마다 topbar 마크업을 따로 손으로
맞추면 탭 하나 추가할 때마다 여러 곳을 고쳐야 하는 문제가 생긴다 - 이 파일 하나로
통일해서, 새 탭이 생기면 NAV_ITEMS만 고치면 전체 페이지에 반영되게 한다.

dashboard.html(Qt 임베드와 공유)에서만 location.protocol 가드가 필요하고, 나머지
페이지는 web_dashboard_server.py만 서빙하므로 가드 없이 곧바로 써도 된다 - 호출부에서
알아서 가드하고 호출한다.

[권한 분리] 여기서 숨기는 메뉴는 UX 편의일 뿐 보안 경계가 아니다 - 실제 차단은
web_dashboard_server.py의 _operator_required/_admin_required가 서버에서 한다.

[웹 대시보드가 꺼지면 서버도 같이 종료] 이 파일이 모든 페이지에서 로드되므로,
여기서 주기적으로 /api/heartbeat를 찔러주는 것만으로 "탭이 열려있는 동안"을
서버가 판단할 수 있다 - 페이지별로 따로 구현할 필요가 없다.

[CSRF] /api/whoami가 세션에 발급된 CSRF 토큰을 함께 내려주면 window.ZVS_CSRF_TOKEN에
저장해두고, zvsFetch()를 쓰는 모든 상태변경 요청(POST/PUT/PATCH/DELETE)에 자동으로
X-CSRF-Token 헤더를 붙인다 - 각 페이지 스크립트가 매번 토큰을 챙길 필요가 없다.

[개인 다크모드 / 탭 진행률 / 알림 / PWA, 2026-09]
- 개인 테마: 서버의 테마 설정(관리자 전역)과 별개로, 각자 브라우저(localStorage)에서만
  라이트/다크를 고를 수 있다. 값이 없으면 기존처럼 서버/페이지 기본을 따른다.
- 탭 진행률/완료 알림: 3초마다 /api/scan/summary를 받아(하트비트 겸용) 스캔 중이면
  탭 제목과 파비콘에 진행률을 표시하고, 실행에서 종료로 바뀌는 순간 브라우저 알림을
  띄운다. 이 로직이 topbar.js에 있으니 스캔 페이지가 아닌 다른 화면에 가 있어도 동작한다.
- PWA: manifest/서비스워커를 등록해 브라우저에서 "앱으로 설치"할 수 있게 한다.
*/
const ZVS_NAV_ITEMS = [
    { key: 'dashboard', label: '대시보드', href: '/', minRole: 'viewer' },
    { key: 'scan', label: '스캔 실행', href: '/scan', minRole: 'viewer' },
    { key: 'assets', label: '자산 관리', href: '/assets', minRole: 'viewer' },
    { key: 'compare', label: '회차 비교', href: '/compare', minRole: 'viewer' },
    { key: 'settings', label: '설정', href: '/settings', minRole: 'viewer' },
];
// [2026-09] 도움말은 우측 상단 링크로, 내 계정/계정 관리/다크모드는 "설정" 안쪽으로 옮겼다.
// 설정 화면 안쪽 탭(내 계정/계정 관리는 별도 페이지지만 같은 "설정" 소속으로 보여준다).
const ZVS_SETTINGS_TABS = [
    { key: 'settings', label: '설정 · 화면', href: '/settings', minRole: 'viewer' },
    { key: 'account', label: '내 계정', href: '/account', minRole: 'viewer' },
    { key: 'accounts', label: '계정 관리', href: '/accounts', minRole: 'admin' },
];
const ZVS_ROLE_RANK = { viewer: 0, operator: 1, admin: 2 };
const ZVS_ROLE_LABEL = { viewer: '조회자', operator: '운영자', admin: '관리자' };
const ZVS_HEARTBEAT_INTERVAL_MS = 20000;
const ZVS_SUMMARY_INTERVAL_MS = 3000;

// ---- 개인 테마 (gui/dashboard_widgets.py의 LIGHT_COLORS/DARK_COLORS와 동일한 값) ----
const ZVS_PALETTES = {
    light: {
        surface_1: '#F5F7FA', surface_2: '#FFFFFF', border: '#E3E7EE', text: '#1B2430', text_secondary: '#5B6675',
        text_muted: '#8B94A3', accent: '#2E6BE6', accent_bg: '#E8EFFE', danger_bg: '#FDE7E7', danger_text: '#C0271F',
        warning_bg: '#FFF6D6', warning_text: '#8A6A00', success_bg: '#E2F5E7', success_text: '#1B8A46', muted_bg: '#EEF1F5',
    },
    dark: {
        surface_1: '#12161C', surface_2: '#1A2029', border: '#2A3240', text: '#E4E8EF', text_secondary: '#9BA5B4',
        text_muted: '#6B7688', accent: '#5B8DEF', accent_bg: '#1B2A4A', danger_bg: '#3A1B1B', danger_text: '#FF6B5C',
        warning_bg: '#3A2E10', warning_text: '#F0C24D', success_bg: '#123322', success_text: '#3ECB7A', muted_bg: '#232A35',
    },
};

function zvsPersonalTheme() {
    try {
        const v = localStorage.getItem('zvs_theme');
        return (v === 'dark' || v === 'light') ? v : null;
    } catch (e) { return null; }
}

// 개인 선택이 있을 때만 팔레트를 돌려준다(dashboard.js가 Chart 색을 맞추는 데도 쓴다).
function zvsThemeColors() {
    const pref = zvsPersonalTheme();
    return pref ? ZVS_PALETTES[pref] : null;
}

function zvsApplyPersonalTheme() {
    const colors = zvsThemeColors();
    if (!colors) return;
    const root = document.documentElement.style;
    Object.keys(colors).forEach(function (k) { root.setProperty('--' + k.replace(/_/g, '-'), colors[k]); });
}

function zvsSetTheme(value) {
    try { localStorage.setItem('zvs_theme', value === 'dark' ? 'dark' : 'light'); } catch (e) {}
    location.reload();
}

function zvsToggleTheme() {
    const current = zvsPersonalTheme() || 'light';
    try { localStorage.setItem('zvs_theme', current === 'dark' ? 'light' : 'dark'); } catch (e) {}
    location.reload();
}
zvsApplyPersonalTheme();

// [CSRF 헤더 자동 첨부] GET은 그대로 fetch()처럼 동작하고, 상태변경 메서드에만
// 헤더를 얹는다. 토큰이 아직 안 채워진 아주 짧은 초기 순간에 호출되면 빈 문자열이
// 붙어 서버가 403을 주는데, 이 경우 에러 메시지가 "새로고침 후 재시도"를 안내한다.
function zvsFetch(url, options) {
    options = options || {};
    const method = (options.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
        options.headers = Object.assign({}, options.headers, { 'X-CSRF-Token': window.ZVS_CSRF_TOKEN || '' });
    }
    return fetch(url, options);
}

function zvsRenderTopbar(activeKey) {
    fetch('/api/whoami')
        .then(function (res) { return res.status === 200 ? res.json() : null; })
        .then(function (data) {
            const username = data ? data.username : '';
            const role = data ? data.role : 'viewer';
            window.ZVS_USERNAME = username;
            window.ZVS_ROLE = role;
            window.ZVS_CSRF_TOKEN = data ? data.csrf_token : '';
            zvsBuildTopbar(activeKey, username, role);
            zvsStartHeartbeat();
            zvsRegisterPwa();
            zvsStartSummaryPoll();
            // [페이지별 쓰기 동작 잠금용] scan.js/assets.js 등이 "이 계정은 조회만
            // 가능하니 버튼을 disabled로 바꿔라" 같은 처리를 하려면 role을 알아야
            // 하는데, 이 fetch는 비동기라 호출 시점엔 아직 role을 모른다. 각
            // 페이지 스크립트가 이 이벤트를 구독해서 role이 확정된 뒤에 UI를
            // 맞추게 한다 - 실제 접근 차단(보안 경계)은 서버가 이미 하고 있으므로
            // 이건 어디까지나 UX(불가능한 버튼을 아예 안 보여주는 것) 목적이다.
            document.dispatchEvent(new CustomEvent('zvs:ready', { detail: { username: username, role: role } }));
        })
        .catch(function () { zvsBuildTopbar(activeKey, '', 'viewer'); });
}

function zvsBuildTopbar(activeKey, username, role) {
    const rank = ZVS_ROLE_RANK[role] || 0;
    const inSettings = activeKey === 'settings' || activeKey === 'account' || activeKey === 'accounts';
    const navActive = inSettings ? 'settings' : activeKey;
    const bar = document.createElement('div');
    bar.style.cssText = 'display:flex;align-items:center;gap:16px;padding:10px 20px;' +
        'background:var(--surface-2, #fff);border-bottom:1px solid var(--border, #E3E7EE);' +
        'font-family:inherit;flex-wrap:wrap;';

    const linksHtml = ZVS_NAV_ITEMS
        .filter(function (item) { return rank >= ZVS_ROLE_RANK[item.minRole]; })
        .map(function (item) {
            const active = item.key === navActive;
            const style = active
                ? 'color:var(--accent, #2E6BE6);font-weight:600;'
                : 'color:var(--text-secondary, #5B6675);';
            return '<a href="' + item.href + '" style="text-decoration:none;font-size:12.5px;' + style + '">' + item.label + '</a>';
        }).join('');

    const roleLabel = ZVS_ROLE_LABEL[role] || role;
    const whoamiHtml = username
        ? '<span id="zvsWhoami" style="color:var(--text-muted, #8B94A3);font-size:12px;">' + username + ' (' + roleLabel + ')</span>'
        : '<span id="zvsWhoami" style="color:var(--text-muted, #8B94A3);font-size:12px;"></span>';

    const shutdownHtml = rank >= ZVS_ROLE_RANK.admin
        ? '<a href="#" id="zvsShutdown" style="color:var(--danger-text, #C0271F);text-decoration:none;font-size:12.5px;">서버 종료</a>'
        : '';

    const helpActive = activeKey === 'help';
    const helpStyle = helpActive ? 'color:var(--accent, #2E6BE6);font-weight:600;' : 'color:var(--text-secondary, #5B6675);';

    bar.innerHTML =
        '<div style="font-weight:700;font-size:13.5px;color:var(--text, #1B2430);">Z-VulnScan 웹 대시보드</div>' +
        linksHtml +
        '<div style="flex:1;"></div>' +
        whoamiHtml +
        '<a href="/help" id="zvsHelpLink" style="text-decoration:none;font-size:12.5px;' + helpStyle + '">도움말</a>' +
        '<a href="/logout" style="color:var(--text-secondary, #5B6675);text-decoration:none;font-size:12.5px;">로그아웃</a>' +
        shutdownHtml;

    document.body.insertBefore(bar, document.body.firstChild);

    if (inSettings) {
        const tabs = document.createElement('div');
        tabs.style.cssText = 'display:flex;gap:4px;padding:8px 20px 0;background:var(--surface-2, #fff);' +
            'border-bottom:1px solid var(--border, #E3E7EE);font-family:inherit;';
        tabs.innerHTML = ZVS_SETTINGS_TABS
            .filter(function (t) { return rank >= ZVS_ROLE_RANK[t.minRole]; })
            .map(function (t) {
                const active = t.key === activeKey;
                const style = active
                    ? 'color:var(--accent, #2E6BE6);font-weight:600;border-bottom:2px solid var(--accent, #2E6BE6);'
                    : 'color:var(--text-secondary, #5B6675);border-bottom:2px solid transparent;';
                return '<a href="' + t.href + '" style="text-decoration:none;font-size:12.5px;padding:6px 12px;' + style + '">' + t.label + '</a>';
            }).join('');
        bar.insertAdjacentElement('afterend', tabs);
    }

    const shutdownLink = document.getElementById('zvsShutdown');
    if (shutdownLink) {
        shutdownLink.addEventListener('click', function (evt) {
            evt.preventDefault();
            if (!confirm('웹 대시보드 서버를 종료합니다. 실행 중인 스캔이 있으면 함께 중지됩니다.\n계속하시겠습니까?')) return;
            zvsFetch('/api/server/shutdown', { method: 'POST' })
                .then(function () {
                    document.body.innerHTML = '<div style="padding:40px;text-align:center;font-family:inherit;color:var(--text-secondary,#5B6675);">' +
                        '서버가 종료되었습니다. 이 창은 닫으셔도 됩니다.</div>';
                })
                .catch(function () {});
        });
    }
}

function zvsStartHeartbeat() {
    const ping = function () {
        zvsFetch('/api/heartbeat', { method: 'POST' }).catch(function () {});
    };
    ping();
    setInterval(ping, ZVS_HEARTBEAT_INTERVAL_MS);
}

// ---- PWA ----
function zvsRegisterPwa() {
    if (!document.querySelector('link[rel="manifest"]')) {
        const link = document.createElement('link');
        link.rel = 'manifest';
        link.href = '/manifest.webmanifest';
        document.head.appendChild(link);
    }
    if (!document.querySelector('link[rel="icon"]')) {
        const icon = document.createElement('link');
        icon.rel = 'icon';
        icon.type = 'image/svg+xml';
        icon.href = '/icon.svg';
        document.head.appendChild(icon);
    }
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(function () {});
}

// ---- 탭 제목/파비콘 진행률 + 완료 알림 ----
const ZVS_BASE_TITLE = document.title;
let zvsPrevRunning = null;

function zvsSetFavicon(href) {
    let link = document.querySelector('link[rel="icon"]');
    if (!link) {
        link = document.createElement('link');
        link.rel = 'icon';
        document.head.appendChild(link);
    }
    link.type = 'image/svg+xml';
    link.href = href;
}

function zvsProgressIcon(percent) {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="#2E6BE6"/>' +
        '<text x="32" y="42" font-size="28" text-anchor="middle" fill="#fff" font-family="sans-serif" font-weight="700">' + percent + '</text></svg>';
    return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

const ZVS_DONE_ICON = 'data:image/svg+xml,' + encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><circle cx="32" cy="32" r="30" fill="#1B8A46"/>' +
    '<path d="M18 33l10 10 19-21" fill="none" stroke="#fff" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/></svg>');

// scan.js가 "스캔 시작" 클릭(사용자 제스처) 시점에 호출해 알림 권한을 요청한다.
function zvsRequestNotify() {
    if ('Notification' in window && Notification.permission === 'default') {
        try { Notification.requestPermission(); } catch (e) {}
    }
}

function zvsApplyScanSummary(sum) {
    if (sum.running) {
        document.title = '[' + sum.percent + '%] ' + ZVS_BASE_TITLE;
        zvsSetFavicon(zvsProgressIcon(sum.percent));
    } else if (zvsPrevRunning === true) {
        document.title = '[완료] ' + ZVS_BASE_TITLE;
        zvsSetFavicon(ZVS_DONE_ICON);
        if ('Notification' in window && Notification.permission === 'granted') {
            try {
                const n = new Notification('Z-VulnScan 스캔 종료', {
                    body: (sum.target ? sum.target + ' - ' : '') + (sum.finished_reason || '완료'),
                    icon: '/icon.svg',
                });
                n.onclick = function () { window.focus(); n.close(); };
            } catch (e) {}
        }
    }
    zvsPrevRunning = !!sum.running;
}

window.addEventListener('focus', function () {
    if (zvsPrevRunning === false && document.title.indexOf('[완료]') === 0) {
        document.title = ZVS_BASE_TITLE;
        zvsSetFavicon('/icon.svg');
    }
});

function zvsStartSummaryPoll() {
    const tick = function () {
        fetch('/api/scan/summary')
            .then(function (res) { return res.status === 200 ? res.json() : null; })
            .then(function (sum) { if (sum) zvsApplyScanSummary(sum); })
            .catch(function () {});
    };
    tick();
    setInterval(tick, ZVS_SUMMARY_INTERVAL_MS);
}
