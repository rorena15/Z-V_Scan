"""requirements.txt의 패키지와 그 전이 의존성의 라이선스 정보를 모아 scanner_engine/gui/web/third_party_licenses.json을 만든다.

설치된 패키지의 메타데이터(importlib.metadata)에서 읽으므로, 실제 배포에 들어가는 환경(CI 빌드 환경 또는 개발 환경)에서
빌드 직전에 실행한다:  python ci/gen_third_party_notices.py

- 라이선스 이름은 메타데이터의 License-Expression / License / Classifier 순으로 찾는다. 못 찾으면 "확인 필요"로 남긴다
  (임의로 추정해서 채우지 않는다).
- 패키지가 라이선스 파일(LICENSE*, COPYING*, NOTICE*)을 함께 배포하면 그 전문을 포함한다.
"""
import json
import os
import re
import sys
from importlib import metadata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "scanner_engine", "gui", "web", "third_party_licenses.json")
LICENSE_FILE_RE = re.compile(r"(^|/)(licen[cs]e|copying|notice)[^/]*$", re.IGNORECASE)
MAX_TEXT = 60000


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_names():
    names = []
    with open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                names.append(re.split(r"[<>=!~\[; ]", line, maxsplit=1)[0])
    return names


def dependency_closure(roots):
    seen, order, stack = set(), [], list(roots)
    while stack:
        name = stack.pop()
        key = norm(name)
        if key in seen:
            continue
        seen.add(key)
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            order.append((name, None))
            continue
        order.append((name, dist))
        for req in dist.requires or []:
            if "extra ==" in req:
                continue
            stack.append(re.split(r"[<>=!~\[; ]", req, maxsplit=1)[0])
    return order


def license_name(meta):
    expr = meta.get("License-Expression")
    if expr:
        return expr.strip()
    lic = (meta.get("License") or "").strip()
    if lic and lic.upper() != "UNKNOWN" and len(lic) < 120 and "\n" not in lic:
        return lic
    if lic and "GNU LESSER GENERAL PUBLIC LICENSE" in lic.upper():
        # License 필드에 라이선스 전문이 통째로 들어있는 패키지(예: pymssql) - 전문의 제목/버전 줄로 이름을 정한다
        m = re.search(r"Version\s+(\d+(?:\.\d+)?)", lic)
        return f"LGPL-{m.group(1)}" if m else "LGPL"
    classifiers = [c.split("::")[-1].strip() for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    classifiers = [c for c in classifiers if c and c != "OSI Approved"]
    if classifiers:
        return " / ".join(classifiers)
    return "확인 필요"


def license_text(dist):
    parts = []
    for f in dist.files or []:
        if LICENSE_FILE_RE.search(str(f).replace("\\", "/")):
            try:
                with open(dist.locate_file(f), encoding="utf-8", errors="replace") as fh:
                    parts.append(f"--- {os.path.basename(str(f))} ---\n" + fh.read().strip())
            except OSError:
                pass
    text = "\n\n".join(parts)
    return text[:MAX_TEXT] + ("\n...(이하 생략)" if len(text) > MAX_TEXT else "")


def main():
    direct = {norm(n) for n in requirement_names()}
    entries, missing = [], []
    for name, dist in dependency_closure(requirement_names()):
        if dist is None:
            missing.append(name)
            continue
        meta = dist.metadata
        entries.append({
            "name": meta.get("Name") or name,
            "version": dist.version,
            "license": license_name(meta),
            "homepage": meta.get("Home-page") or (meta.get("Project-URL") or "").split(",")[-1].strip(),
            "direct": norm(meta.get("Name") or name) in direct,
            "text": license_text(dist),
        })
    # pip 메타데이터에 없는, 패키지에 포함돼 배포되는 구성요소의 고지(직접 관리)
    entries.append({
        "name": "Qt WebEngine (Chromium 포함)",
        "version": "PySide6 6.x에 포함",
        "license": "LGPL-3.0 / GPL (Qt) + Chromium 서드파티 라이선스 다수(가장 제한적인 것은 LGPL-2.1)",
        "homepage": "https://doc.qt.io/qt-6/qtwebengine-licensing.html",
        "direct": False,
        "text": "대시보드 화면(QtWebEngine)이 사용하는 Chromium에는 150여 개 서드파티 구성요소가 들어 있습니다. "
                "각 구성요소의 라이선스 목록과 전문은 위 홈페이지(Qt WebEngine Licensing)에서 확인할 수 있습니다.",
    })
    entries.sort(key=lambda e: (not e["direct"], e["name"].lower()))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump({"generated_by": "ci/gen_third_party_notices.py", "packages": entries}, f, ensure_ascii=False, indent=1)
    unknown = [e["name"] for e in entries if e["license"] == "확인 필요"]
    print(f"{len(entries)} packages -> {OUT}")
    if missing:
        print("설치되지 않아 건너뜀:", ", ".join(missing))
    if unknown:
        print("라이선스 확인 필요:", ", ".join(unknown))


if __name__ == "__main__":
    sys.exit(main())
