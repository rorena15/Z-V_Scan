"""룰 랩 - 룰 판정을 화면에서 시험해 보는 개발/검수용 도구 (고객용 exe에는 들어가지 않는다).

  python tests\\rule_lab.py            # 또는 run_rulelab.bat  -> 브라우저가 자동으로 열림

- 룰을 고르고, 그 룰이 읽는 설정값(레지스트리/보안정책/파일)을 입력하면 이 PC의 임시 환경에서 룰 명령을
  실제로 실행해 세부기준별 출력과 최종 판정(양호/부분만족/취약...)을 보여준다. 값을 비우면 '미설정'.
- 결과를 시나리오(tests/scenarios/custom.json)로 저장하면 이후 `run_tests.bat`에 회귀 테스트로 포함된다.
- 표준 라이브러리만 사용, 127.0.0.1에서만 열림. 실제 레지스트리/시스템 파일은 읽지도 쓰지도 않는다
  (임시 키/폴더만 사용 - _fixture_env.py 참고). Ctrl+C로 종료."""
import http.server
import json
import os
import socketserver
import sys
import threading
import webbrowser
from urllib.parse import parse_qs, urlparse

import _fixture_env as fx
import _helpers as h

HERE = os.path.dirname(os.path.abspath(__file__))
SCENARIO_DIR = os.path.join(HERE, 'scenarios')
CUSTOM_FILE = os.path.join(SCENARIO_DIR, 'custom.json')
RUN_LOCK = threading.Lock()   # 임시 레지스트리/폴더를 쓰는 실행은 한 번에 하나씩


def load_scenarios():
    items = []
    if os.path.isdir(SCENARIO_DIR):
        for name in sorted(os.listdir(SCENARIO_DIR)):
            if not name.endswith('.json'):
                continue
            with open(os.path.join(SCENARIO_DIR, name), encoding='utf-8') as f:
                for i, sc in enumerate(json.load(f)):
                    items.append({"file": name, "index": i, "scenario": sc})
    return items


def rule_detail(code):
    for filename, osname in fx.LOCAL_RULESETS.items():
        rules = h.load_rules(filename)
        if code in rules:
            r = rules[code]
            return {
                "code": code, "name": r['name'], "importance": r['importance'], "category": r.get('category', ''),
                "description": r.get('description', ''), "remediation": r.get('remediation', ''),
                "os": osname, "command": r.get('command', ''),
                "criteria": [{"label": c['label'], "command": c.get('command', '')} for c in r.get('criteria') or []],
                "suggest": fx.suggest_env(r, osname),
            }
    raise KeyError(code)


def clean_reg_rows(rows):
    """화면의 레지스트리 행 -> 시나리오 저장용 {경로: {이름: 값}} (빈 값은 미설정이라 뺀다, 숫자 문자열은 int)."""
    out = {}
    for row in rows or []:
        v = row.get('value')
        if v is None or str(v).strip() == '':
            continue
        v = str(v).strip()
        out.setdefault(row['path'].strip(), {})[row['name'].strip()] = int(v) if v.lstrip('-').isdigit() else v
    return out


def clean_file_rows(rows):
    return {r['path'].strip(): r.get('content', '') for r in rows or [] if str(r.get('content', '')).strip() != ''}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ZVulnRuleLab/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype='application/json; charset=utf-8'):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self):
        # DNS rebinding 방어: 다른 도메인이 127.0.0.1로 향하게 만들어 이 서버를 부르는 것을 막는다.
        host = (self.headers.get('Host') or '').split(':')[0]
        return host in ('127.0.0.1', 'localhost')

    def _body(self):
        n = int(self.headers.get('Content-Length') or 0)
        return json.loads(self.rfile.read(n) or b'{}')

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "forbidden host"})
        url = urlparse(self.path)
        try:
            if url.path == '/':
                with open(os.path.join(HERE, 'rule_lab.html'), 'rb') as f:
                    return self._send(200, f.read(), 'text/html; charset=utf-8')
            if url.path == '/api/rules':
                return self._send(200, fx.list_local_rules())
            if url.path == '/api/rule':
                return self._send(200, rule_detail(parse_qs(url.query)['code'][0]))
            if url.path == '/api/scenarios':
                return self._send(200, load_scenarios())
            self._send(404, {"error": "not found"})
        except KeyError:
            self._send(404, {"error": "룰을 찾을 수 없습니다."})

    def do_POST(self):
        if not self._host_ok() or self.headers.get('X-ZVS-Lab') != '1':
            return self._send(403, {"error": "forbidden"})
        try:
            data = self._body()
            path = urlparse(self.path).path
            if path == '/api/run':
                with RUN_LOCK:
                    res = fx.evaluate(data['rule'], reg=data.get('reg'), secpol=data.get('secpol'),
                                      files=clean_file_rows(data.get('files')))
                return self._send(200, res)
            if path == '/api/scenarios/save':
                sc = {"name": (data.get('name') or data['rule']).strip(), "rule": data['rule'],
                      "expect": data['expect']}
                reg = clean_reg_rows(data.get('reg'))
                files = clean_file_rows(data.get('files'))
                if reg:
                    sc['reg'] = reg
                if (data.get('secpol') or '').strip():
                    sc['secpol'] = data['secpol']
                if files:
                    sc['files'] = files
                if data.get('detail_contains'):
                    sc['detail_contains'] = data['detail_contains']
                existing = []
                if os.path.exists(CUSTOM_FILE):
                    with open(CUSTOM_FILE, encoding='utf-8') as f:
                        existing = json.load(f)
                existing.append(sc)
                os.makedirs(SCENARIO_DIR, exist_ok=True)
                with open(CUSTOM_FILE, 'w', encoding='utf-8') as f:
                    json.dump(existing, f, ensure_ascii=False, indent=2)
                return self._send(200, {"ok": True, "count": len(existing)})
            if path == '/api/scenarios/delete':      # custom.json의 시나리오만 삭제 가능(example.json 등은 보호)
                with open(CUSTOM_FILE, encoding='utf-8') as f:
                    existing = json.load(f)
                del existing[int(data['index'])]
                with open(CUSTOM_FILE, 'w', encoding='utf-8') as f:
                    json.dump(existing, f, ensure_ascii=False, indent=2)
                return self._send(200, {"ok": True})
            if path == '/api/scenarios/run-all':
                results = []
                with RUN_LOCK:
                    for item in load_scenarios():
                        sc = item['scenario']
                        try:
                            ok, res = fx.run_scenario(sc)
                            results.append({"file": item['file'], "index": item['index'], "name": sc.get('name', sc['rule']),
                                            "ok": ok, "expected": sc.get('expect'), "status": res['status'],
                                            "detail": res['detail'], "missing": res['missing_phrases']})
                        except Exception as e:  # noqa: BLE001
                            results.append({"file": item['file'], "index": item['index'],
                                            "name": sc.get('name', sc['rule']), "ok": False,
                                            "expected": sc.get('expect'), "status": "ERROR", "detail": str(e), "missing": []})
                return self._send(200, results)
            self._send(404, {"error": "not found"})
        except (ValueError, KeyError, RuntimeError) as e:
            self._send(400, {"error": str(e)})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": f"{type(e).__name__}: {e}"})


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    port = int(os.environ.get('ZVS_LAB_PORT', '8765'))
    for candidate in range(port, port + 20):
        try:
            server = Server(('127.0.0.1', candidate), Handler)
            break
        except OSError:
            continue
    else:
        raise SystemExit("사용 가능한 포트를 찾지 못했습니다.")
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"룰 랩 실행 중: {url}   (종료: Ctrl+C)")
    if not os.environ.get('ZVS_LAB_NO_BROWSER'):
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료합니다.")


if __name__ == '__main__':
    main()
