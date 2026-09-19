// 설치 가능(PWA) 조건만 채우는 no-op 서비스 워커 - 캐시/오프라인 동작 없음(요청을 가로채지 않음).
self.addEventListener('install', function () { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });
