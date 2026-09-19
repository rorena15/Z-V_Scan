/*
Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
This software is proprietary and confidential.
Unauthorized copying, modification, distribution, or reverse engineering
of this file, via any medium, is strictly prohibited.
*/
zvsRenderTopbar('help');

let helpCategories = [];
let activeIndex = 0;

function $(id) { return document.getElementById(id); }

function renderNav() {
    const nav = $('categoryNav');
    nav.innerHTML = '';
    helpCategories.forEach(function (cat, i) {
        const btn = document.createElement('button');
        btn.textContent = cat.title;
        btn.className = i === activeIndex ? 'active' : '';
        btn.addEventListener('click', function () { showCategory(i); });
        nav.appendChild(btn);
    });
}

function showCategory(index) {
    activeIndex = index;
    const cat = helpCategories[index];
    if (!cat) return;
    $('detailTitle').textContent = cat.title;
    // [서버에서 이미 신뢰된 정적 콘텐츠] detail_html은 사용자 입력이 아니라
    // gui/help_texts.py의 고정 문구를 gui/help_dialog.py의 서식 변환 로직으로
    // HTML화한 결과다 - innerHTML로 그대로 렌더링해도 XSS 경로가 없다.
    $('detailBody').innerHTML = cat.detail_html;
    renderNav();
}

fetch('/api/help')
    .then(function (res) {
        if (res.status === 401) { location.href = '/login'; return null; }
        return res.json();
    })
    .then(function (data) {
        if (!data) return;
        helpCategories = data;
        showCategory(0);
    });
