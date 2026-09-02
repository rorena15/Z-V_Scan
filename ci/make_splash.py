"""
assets/splash.png 생성 스크립트.

PyInstaller --onefile은 실행할 때마다 번들 전체를 %TEMP%에 풀고 나서야
앱 창이 뜬다 - 그 동안 화면이 그냥 멈춰 보이는 게 "부팅 속도" 불만의
실제 체감 원인이었다. onedir로 바꾸는 대신(사용자가 onefile 유지를 선택함,
2026-09-02), PyInstaller의 --splash 기능으로 그 대기 시간 동안 "실행 중"
안내 화면을 띄운다 - 압축 해제 시작과 동시에 네이티브 스플래시 창이 뜨고,
main.py가 메인 윈도우를 띄운 직후 pyi_splash.close()로 닫는다.

한 번 실행해서 assets/splash.png를 생성해두면 되고(정적 에셋으로 커밋),
빌드 때마다 다시 만들 필요는 없다 - 텍스트/색을 바꿀 때만 재실행.

[2026-09-02] 실제로 배포판에 들어가는 assets/splash.png는 이 스크립트가 만든
게 아니라 Z-VulnScan_Build_Work/splash_Image.psd(레이더 테마의 기존 디자인
에셋)를 600x400 PNG로 내보낸 것으로 교체했다 - 브랜드에 맞는 완성도 높은
디자인이 이미 있어서 그쪽을 우선했다. 이 스크립트는 그 psd가 없거나 문구만
빠르게 바꿔 넣고 싶을 때 쓰는 대체 수단으로 남겨둔다.
"""
import os

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# gui/dashboard_widgets.py의 DARK_COLORS와 맞춘다 - 스플래시는 테마 결정(설정 로드) 전에
# 뜨므로 라이트/다크를 고를 수 없어, 두 테마 모두에서 무난한 다크를 고정으로 쓴다.
BG = "#12161C"
BG_BOTTOM = "#161C26"
ACCENT = "#5B8DEF"
TEXT = "#E4E8EF"
TEXT_MUTED = "#6B7688"

W, H = 480, 300
FONT_DIR = r"C:\Windows\Fonts"


def _font(name, size):
    return ImageFont.truetype(os.path.join(FONT_DIR, name), size)


def main():
    img = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(img)

    # 상하 미세한 그라데이션 (완전 단색보다 입체감)
    for y in range(H):
        t = y / H
        r = int(int(BG[1:3], 16) * (1 - t) + int(BG_BOTTOM[1:3], 16) * t)
        g = int(int(BG[3:5], 16) * (1 - t) + int(BG_BOTTOM[3:5], 16) * t)
        b = int(int(BG[5:7], 16) * (1 - t) + int(BG_BOTTOM[5:7], 16) * t)
        draw.line([(0, y), (W, y)], fill=(r, g, b))

    # 앱 아이콘
    icon_path = os.path.join(ROOT, "app_icon.ico")
    if os.path.exists(icon_path):
        icon = Image.open(icon_path)
        icon = icon.convert("RGBA").resize((64, 64), Image.LANCZOS)
        img.paste(icon, (W // 2 - 32, 46), icon)

    # 타이틀
    title_font = _font("malgunbd.ttf", 30)
    title = "Z-VulnScan"
    tw = draw.textlength(title, font=title_font)
    draw.text((W / 2 - tw / 2, 124), title, font=title_font, fill=ACCENT)

    sub_font = _font("malgun.ttf", 14)
    sub = "Professional Edition"
    sw = draw.textlength(sub, font=sub_font)
    draw.text((W / 2 - sw / 2, 162), sub, font=sub_font, fill=TEXT)

    # 안내 문구 (실제 "실행 중" 체감을 주는 핵심 문구)
    status_font = _font("malgun.ttf", 13)
    status = "엔진을 초기화하는 중입니다..."
    stw = draw.textlength(status, font=status_font)
    draw.text((W / 2 - stw / 2, 224), status, font=status_font, fill=TEXT_MUTED)

    # 하단 액센트 바 (대시보드 카드의 좌측 4px 액센트 보더와 톤 통일)
    draw.rectangle([0, H - 4, W, H], fill=ACCENT)

    out_dir = os.path.join(ROOT, "assets")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "splash.png")
    img.save(out_path)
    print(f"saved: {out_path}")


if __name__ == "__main__":
    main()
