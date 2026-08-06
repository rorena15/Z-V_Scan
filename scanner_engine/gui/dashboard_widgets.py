# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[Phase 3: UI 재구성] 라이트 테마 대시보드 컴포넌트 라이브러리.

색상은 COLORS/STATUS_STYLE 딕셔너리 하나로 관리한다 - 배지/범례/사이드바/로그 도킹 등
main_window.py의 다른 크롬(chrome) 요소도 이 값을 그대로 import해서 쓰며, 색을 바꿀 때
여기 한 곳만 고치면 전체에 반영된다.

주의: risk_level/importance 값은 영어(Critical/High 등)가 아니라 KISA 룰 JSON의
'importance' 필드를 그대로 저장한 한글 3단계('상'/'중'/'하')다. 리포트(엑셀/PDF)에서도
동일한 값을 쓰므로, 이 모듈의 STATUS_STYLE/RISK_TEXT_COLOR 키도 실제 저장값과 맞춘다.
"""
from PySide6.QtWidgets import (
    QWidget, QFrame, QLabel, QLineEdit, QComboBox, QSlider, QCheckBox,
    QPushButton, QVBoxLayout, QHBoxLayout, QGridLayout,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QGraphicsDropShadowEffect
)
from PySide6.QtCore import Qt, QRectF, QVariantAnimation, QEasingCurve, Signal
from PySide6.QtGui import QColor, QIcon, QPixmap, QPainter, QPen


# ----------------------------------------------------------------------
# 색상 토큰 - [다크 테마 대응] COLORS는 항상 같은 dict "객체"를 유지하고
# set_theme()이 그 내용만 in-place로 바꿔치기한다. 이 모듈의 위젯들은 전부
# __init__ 안에서 COLORS[...]/STATUS_STYLE[...]을 그때그때 조회하므로,
# set_theme()을 위젯 생성 "전"에 한 번만 호출해두면 이후 만들어지는 모든
# 카드가 자동으로 맞는 테마 색을 쓴다 (COLORS 이름을 다른 dict로 재바인딩하면
# 이미 `from ... import COLORS`로 참조를 가져간 다른 모듈에는 반영되지 않으므로
# 반드시 .clear()+.update()로 내용만 바꾼다).
# ----------------------------------------------------------------------
# [UI/UX 개선 - "신뢰할 수 있는 작업대" 방향] 국산 보안 콘솔(VADA/엑소스피어/
# 솔리드스텝)·Qualys 계열이 공유하는 문법(쿨톤 배경, 파랑 액센트, 부드러운 카드,
# 둥근 배지형 심각도 표시)으로 재설계됨. 토큰 이름/구조는 그대로 두고 값만 교체.
LIGHT_COLORS = {
    "surface_1": "#F5F7FA",   # 지표카드 기본 배경, 사이드바 (쿨톤 캔버스)
    "surface_2": "#FFFFFF",   # 카드 배경 (Scan configuration, Assets 테이블) - 캔버스 위에 뜬 흰 카드
    "border": "#E3E7EE",
    "text": "#1B2430",
    "text_secondary": "#5B6675",
    "text_muted": "#8B94A3",
    "accent": "#2E6BE6",
    "accent_bg": "#E8EFFE",
    "danger_bg": "#FDE7E7",
    "danger_text": "#C0271F",
    "warning_bg": "#FFF6D6",
    "warning_text": "#8A6A00",
    "success_bg": "#E2F5E7",
    "success_text": "#1B8A46",
    "muted_bg": "#EEF1F5",
}

DARK_COLORS = {
    "surface_1": "#12161C",   # 지표카드 기본 배경, 사이드바 (라이트와 같은 쿨톤 계열의 어두운 버전)
    "surface_2": "#1A2029",   # 카드 배경 - surface_1보다 살짝 밝게 해서 입체감을 준다
    "border": "#2A3240",
    "text": "#E4E8EF",
    "text_secondary": "#9BA5B4",
    "text_muted": "#6B7688",
    "accent": "#5B8DEF",      # 어두운 배경에서도 또렷하도록 라이트 액센트보다 밝게 보정
    "accent_bg": "#1B2A4A",
    "danger_bg": "#3A1B1B",
    "danger_text": "#FF6B5C",
    "warning_bg": "#3A2E10",
    "warning_text": "#F0C24D",
    "success_bg": "#123322",
    "success_text": "#3ECB7A",
    "muted_bg": "#232A35",
}

COLORS = dict(LIGHT_COLORS)
STATUS_STYLE = {}
RISK_TEXT_COLOR = {}
HOSTNAME_SOURCE_STYLE = {}


def _rebuild_derived_styles():
    """COLORS가 바뀔 때마다 그 값을 참조하는 STATUS_STYLE/RISK_TEXT_COLOR도 다시 만든다."""
    STATUS_STYLE.clear()
    STATUS_STYLE.update({
        # status -> (배경, 텍스트, 표시라벨). 여기 하나만 고치면 배지/범례/리포트 전부 동기화됨.
        "VULNERABLE": (COLORS["danger_bg"], COLORS["danger_text"], "Vulnerable"),
        "PARTIAL":    (COLORS["warning_bg"], COLORS["warning_text"], "Partial"),
        "SAFE":       (COLORS["success_bg"], COLORS["success_text"], "Safe"),
        "WARNING":    (COLORS["warning_bg"], COLORS["warning_text"], "Warning"),
        "MANUAL":     (COLORS["muted_bg"], COLORS["text_secondary"], "Manual check"),
        "NA":         (COLORS["muted_bg"], COLORS["text_secondary"], "N/A"),
        "ERROR":      (COLORS["muted_bg"], COLORS["text_secondary"], "Connection error"),
    })
    RISK_TEXT_COLOR.clear()
    RISK_TEXT_COLOR.update({
        # 실제 TBL_SCAN_RESULT.risk_level 저장값 - worker.py가 KISA importance(상/중/하)를
        # 판정 상태(VULNERABLE/PARTIAL)에 따라 영문 5단계로 변환해서 저장한다 (worker.py 참고).
        "Critical": COLORS["danger_text"],
        "High": COLORS["warning_text"],
        "Medium": COLORS["warning_text"],
        "Low": COLORS["text_secondary"],
        "Info": COLORS["text_muted"],
    })
    HOSTNAME_SOURCE_STYLE.clear()
    HOSTNAME_SOURCE_STYLE.update({
        # worker.py.discover_target()/_save_hostname_update_to_db()가 채우는
        # hostname_source 값 -> (배경, 텍스트). "실측"(인증 접속 확인)이 가장 신뢰도가
        # 높고, "추정"(vendor placeholder)이 가장 낮다는 걸 색으로도 드러낸다.
        "역DNS": (COLORS["accent_bg"], COLORS["accent"]),
        "매핑": (COLORS["success_bg"], COLORS["success_text"]),
        "실측": (COLORS["success_bg"], COLORS["success_text"]),
        "수동입력": (COLORS["muted_bg"], COLORS["text_secondary"]),
        "추정": (COLORS["warning_bg"], COLORS["warning_text"]),
    })


def set_theme(theme_name):
    """main_window.py가 위젯을 만들기 "전"에 한 번 호출한다 (theme_name: 'light' 또는 'dark')."""
    COLORS.clear()
    COLORS.update(DARK_COLORS if theme_name == "dark" else LIGHT_COLORS)
    _rebuild_derived_styles()


_rebuild_derived_styles()


def make_line_icon(kind: str, color_hex: str, size: int = 18) -> QIcon:
    """[UI/UX 개선 - "신뢰할 수 있는 작업대"] 목업(zvulnscan_design_directions)의
    미니멀 라인 아이콘을 외부 이미지 파일 없이 QPainter로 그때그때 그린다 - 빌드에
    아이콘 리소스를 추가로 번들할 필요가 없고, 팔레트/다크모드 전환 시 색만 바꾸면
    된다(파일 기반 아이콘이었다면 테마마다 별도 에셋이 필요했을 것).
    kind: 'grid'(대시보드) | 'search'(스캔) | 'folder'(자산) | 'doc'(리포트) |
          'compare'(교차검증) | 'help' | 'settings' | 'asset' | 'warning' | 'info' | 'link'
    """
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    pen = QPen(QColor(color_hex))
    pen.setWidthF(1.6)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    m = size * 0.16  # 여백

    if kind in ("grid", "asset"):
        half = (size - 2 * m) / 2 - 2
        painter.drawRoundedRect(QRectF(m, m, half, half), 2, 2)
        painter.drawRoundedRect(QRectF(size - m - half, m, half, half), 2, 2)
        painter.drawRoundedRect(QRectF(m, size - m - half, half, half), 2, 2)
        painter.drawRoundedRect(QRectF(size - m - half, size - m - half, half, half), 2, 2)
    elif kind == "search":
        r = size * 0.28
        cx, cy = size * 0.42, size * 0.42
        painter.drawEllipse(QRectF(cx - r, cy - r, r * 2, r * 2))
        painter.drawLine(int(cx + r * 0.7), int(cy + r * 0.7), int(size - m), int(size - m))
    elif kind == "folder":
        painter.drawRoundedRect(QRectF(m, size * 0.36, size - 2 * m, size * 0.42), 2, 2)
        painter.drawLine(int(m), int(size * 0.36), int(m + size * 0.28), int(size * 0.36))
        painter.drawLine(int(m + size * 0.28), int(size * 0.36), int(m + size * 0.38), int(size * 0.24))
        painter.drawLine(int(m + size * 0.38), int(size * 0.24), int(size - m), int(size * 0.24))
        painter.drawLine(int(size - m), int(size * 0.24), int(size - m), int(size * 0.36))
    elif kind == "doc":
        painter.drawRoundedRect(QRectF(m + 1, m, size - 2 * m - 2, size - 2 * m), 2, 2)
        for i in range(3):
            y = size * 0.38 + i * size * 0.16
            painter.drawLine(int(m + 4), int(y), int(size - m - 4), int(y))
    elif kind == "compare":
        painter.drawRoundedRect(QRectF(m, m, size * 0.5, size * 0.5), 2, 2)
        painter.drawRoundedRect(QRectF(size - m - size * 0.5, size - m - size * 0.5, size * 0.5, size * 0.5), 2, 2)
    elif kind == "help":
        r = size / 2 - m
        painter.drawEllipse(QRectF(m, m, r * 2, r * 2))
        font = painter.font()
        font.setBold(True)
        font.setPointSizeF(size * 0.42)
        painter.setFont(font)
        painter.drawText(pixmap.rect(), Qt.AlignCenter, "?")
    elif kind == "settings":
        r_out = size / 2 - m
        r_in = r_out * 0.42
        cx = cy = size / 2
        painter.drawEllipse(QRectF(cx - r_out, cy - r_out, r_out * 2, r_out * 2))
        painter.drawEllipse(QRectF(cx - r_in, cy - r_in, r_in * 2, r_in * 2))
    elif kind == "warning":
        top = (size / 2, m)
        left = (m, size - m)
        right = (size - m, size - m)
        painter.drawLine(int(top[0]), int(top[1]), int(left[0]), int(left[1]))
        painter.drawLine(int(left[0]), int(left[1]), int(right[0]), int(right[1]))
        painter.drawLine(int(right[0]), int(right[1]), int(top[0]), int(top[1]))
        painter.drawPoint(int(size / 2), int(size * 0.68))
    elif kind == "info":
        r = size / 2 - m
        painter.drawEllipse(QRectF(size / 2 - r, size / 2 - r, r * 2, r * 2))
        painter.drawLine(int(size / 2), int(size * 0.42), int(size / 2), int(size * 0.68))
    elif kind == "link":
        r = size / 2 - m
        painter.drawEllipse(QRectF(size / 2 - r, size / 2 - r, r * 2, r * 2))
        painter.drawLine(int(size * 0.36), int(size * 0.36), int(size * 0.64), int(size * 0.64))

    painter.end()
    return QIcon(pixmap)


def _apply_card_shadow(widget, blur=22, y_offset=3, alpha=28):
    """[미니멀 인상 완화] 카드에 은은한 그림자를 줘서 배경과 구분되는 입체감을 준다."""
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setOffset(0, y_offset)
    effect.setColor(QColor(0, 0, 0, alpha))
    widget.setGraphicsEffect(effect)
    return effect


class HoverLiftFrame(QFrame):
    """[UI/UX 개선 - 인터랙션] 마우스를 올리면 그림자가 살짝 커지면서 카드가 "떠 보이는"
    반응을 준다(Z-VulnScan_QML_ROI분석.md의 Option A - QPropertyAnimation 저비용
    인터랙션 중 하나). QGraphicsDropShadowEffect는 Qt 프로퍼티라 애니메이션 가능.

    [버그 수정 - 실사용 중 크래시 확인] 처음엔 매 hover마다 QVariantAnimation을 새로
    만들고 QAbstractAnimation.DeleteWhenStopped로 시작했다 - 이 플래그는 애니메이션이
    "자연 종료"돼도 C++ 객체를 스스로 삭제하는데, 그 다음 hover에서 이전 파이썬 참조에
    .stop()을 호출하면 "Internal C++ object already deleted" RuntimeError로 죽는 게
    scan_debug.log에서 실측 확인됐다(빠르게 마우스를 들락거리면 재현). 인스턴스당
    애니메이션 객체를 __init__에서 한 번만 만들어 재사용하고 절대 자기 자신을
    지우지 않게 해서(기본 KeepWhenStopped) 이 경합을 근본적으로 없앤다."""
    def __init__(self, base_blur=16, base_y=2, hover_blur=26, hover_y=6, alpha=24, parent=None):
        super().__init__(parent)
        self._base_blur = base_blur
        self._base_y = base_y
        self._hover_blur = hover_blur
        self._hover_y = hover_y
        self._shadow = _apply_card_shadow(self, blur=base_blur, y_offset=base_y, alpha=alpha)
        self._shadow_start = (base_blur, base_y)
        self._shadow_target = (base_blur, base_y)
        self._hover_anim = QVariantAnimation(self)
        self._hover_anim.setDuration(150)
        self._hover_anim.setEasingCurve(QEasingCurve.OutCubic)
        self._hover_anim.valueChanged.connect(self._apply_shadow_progress)

    def _apply_shadow_progress(self, t):
        sb, sy = self._shadow_start
        tb, ty = self._shadow_target
        self._shadow.setBlurRadius(sb + (tb - sb) * t)
        self._shadow.setOffset(0, sy + (ty - sy) * t)

    def _animate_shadow(self, target_blur, target_y):
        self._hover_anim.stop()
        self._shadow_start = (self._shadow.blurRadius(), self._shadow.yOffset())
        self._shadow_target = (target_blur, target_y)
        self._hover_anim.setStartValue(0.0)
        self._hover_anim.setEndValue(1.0)
        self._hover_anim.start()

    def enterEvent(self, event):
        self._animate_shadow(self._hover_blur, self._hover_y)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._animate_shadow(self._base_blur, self._base_y)
        super().leaveEvent(event)


# ----------------------------------------------------------------------
# 재사용 컴포넌트
# ----------------------------------------------------------------------
class InfoIcon(QLabel):
    """라벨 옆에 붙는 도움말 표시. hover 시 QToolTip 표시.
    이모지/유니코드 원문자는 Windows 환경에서 깨져 보일 수 있어(현장에서 실측 확인됨)
    항상 렌더링되는 ASCII "(?)"로 표기한다."""
    def __init__(self, tooltip_text: str, parent=None):
        super().__init__("(?)", parent)
        self.setToolTip(tooltip_text)
        self.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px;")
        self.setCursor(Qt.WhatsThisCursor)


class LabelWithHelp(QWidget):
    """'Target range (?)' 같은 라벨+도움말 아이콘 조합."""
    def __init__(self, text: str, tooltip_text: str, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        label = QLabel(text)
        label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px;")
        layout.addWidget(label)
        layout.addWidget(InfoIcon(tooltip_text))
        layout.addStretch()


class StatusBadge(QLabel):
    """상태 pill 배지. status는 STATUS_STYLE의 키(VULNERABLE/PARTIAL/SAFE/MANUAL/...)."""
    def __init__(self, status: str, parent=None):
        super().__init__(parent)
        # worker.py가 일부 메타 항목(INFO-00, SYS-*, TCP-22 등)에 "Safe"(혼합 대소문자)를
        # 그대로 저장하므로, 대소문자 무관하게 매칭한다.
        bg, fg, label = STATUS_STYLE.get((status or "").upper(), STATUS_STYLE["MANUAL"])
        self.setText(label)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet(f"""
            background-color: {bg};
            color: {fg};
            border-radius: 9px;
            padding: 2px 10px;
            font-size: 11px;
        """)
        self.setFixedHeight(20)


class HostnameSourceBadge(QLabel):
    """[UI/UX 개선 - hostname 출처 배지] hostname이 역DNS/자산목록 매핑/인증 접속 실측/
    수동입력/추정(vendor placeholder) 중 어디서 왔는지 자산 목록에서 바로 보여준다.
    OT망에서 DNS 없이도 hostname을 확보한다는 게 이 제품의 판매 차별점이라
    (§세션 논의), 그 근거를 화면에서 직접 증명하는 용도."""
    def __init__(self, source: str, parent=None):
        super().__init__(parent)
        source = (source or "").strip()
        if not source:
            self.setText("")
            self.setStyleSheet("border:none;")
            return
        bg, fg = HOSTNAME_SOURCE_STYLE.get(source, (COLORS["muted_bg"], COLORS["text_secondary"]))
        self.setText(source)
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet(f"""
            background-color: {bg};
            color: {fg};
            border-radius: 8px;
            padding: 1px 8px;
            font-size: 10.5px;
        """)
        self.setFixedHeight(18)


class LegendDot(QWidget):
    """범례용 색점 + 텍스트."""
    def __init__(self, color_hex: str, text: str, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        dot = QLabel()
        dot.setFixedSize(8, 8)
        dot.setStyleSheet(f"background-color: {color_hex}; border-radius: 4px;")
        layout.addWidget(dot)
        txt = QLabel(text)
        txt.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11px;")
        layout.addWidget(txt)


class MetricCard(HoverLiftFrame):
    """지표 카드 (Assets scanned / Critical findings 등). tone: 'default'|'danger'|'warning'."""
    def __init__(self, label: str, value: str, tone: str = "default",
                 tooltip_text: str = None, icon_kind: str = None, parent=None):
        super().__init__(base_blur=16, base_y=2, alpha=22, parent=parent)
        self.tone = tone
        bg_map = {
            "default": COLORS["surface_1"],
            "danger": COLORS["danger_bg"],
            "warning": COLORS["warning_bg"],
        }
        text_map = {
            "default": COLORS["text"],
            "danger": COLORS["danger_text"],
            "warning": COLORS["warning_text"],
        }
        accent_map = {
            "default": COLORS["accent"],
            "danger": COLORS["danger_text"],
            "warning": COLORS["warning_text"],
        }
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {bg_map[tone]};
                border-radius: 10px;
                border-left: 4px solid {accent_map[tone]};
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 11, 14, 11)
        layout.setSpacing(4)

        label_row = QHBoxLayout()
        label_row.setSpacing(4)
        label_widget = QLabel(label)
        label_widget.setStyleSheet(
            f"color: {text_map[tone] if tone != 'default' else COLORS['text_secondary']}; font-size: 12px; border:none;"
        )
        label_row.addWidget(label_widget)
        if tooltip_text:
            label_row.addWidget(InfoIcon(tooltip_text))
        label_row.addStretch()
        if icon_kind:
            # [UI/UX 개선] 목업의 카드 우상단 아이콘 배지 - 톤별 배경(연한 accent/danger/
            # warning 배경)에 같은 톤의 아이콘을 얹는다.
            badge_bg = {"default": COLORS["accent_bg"], "danger": "#F6D8D3", "warning": "#F2E2B4"}.get(tone, COLORS["accent_bg"])
            badge = QLabel()
            badge.setFixedSize(26, 26)
            badge.setAlignment(Qt.AlignCenter)
            badge.setStyleSheet(f"background-color: {badge_bg}; border-radius: 7px;")
            badge.setPixmap(make_line_icon(icon_kind, accent_map[tone]).pixmap(15, 15))
            label_row.addWidget(badge)
        layout.addLayout(label_row)

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"color: {text_map[tone]}; font-size: 24px; font-weight: 600; border:none;")
        layout.addWidget(self.value_label)

        # [버그 수정] HoverLiftFrame과 동일한 이유로 인스턴스당 하나만 만들어 재사용한다
        # (매번 새로 만들고 DeleteWhenStopped로 시작하면 다음 호출에서 이미 삭제된 C++
        # 객체에 .stop()을 호출해 크래시 - scan_debug.log에서 실측 확인됨).
        self._count_anim = QVariantAnimation(self)
        self._count_anim.setDuration(500)
        self._count_anim.setEasingCurve(QEasingCurve.OutCubic)
        self._count_anim.valueChanged.connect(lambda v: self.value_label.setText(str(v)))

        # [UI/UX 개선] '전 회차 대비' 추이 - 데이터가 준비되기 전까지는 숨겨둔다(빈 줄이
        # 아니라 아예 자리 자체가 없어야 카드가 헐렁해 보이지 않는다). set_trend()가
        # 실제 값을 받으면 그때 표시한다.
        self.trend_label = QLabel("")
        self.trend_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; border:none;")
        self.trend_label.setVisible(False)
        layout.addWidget(self.trend_label)

    def set_value(self, value: str):
        """[UI/UX 개선 - 인터랙션] 숫자가 바뀔 때 그냥 스냅되지 않고 이전 값에서
        새 값으로 카운트업 애니메이션한다. value가 순수 정수 문자열이 아니면(예외
        상황 대비) 애니메이션 없이 그대로 표시한다."""
        try:
            old_num = int(self.value_label.text())
            new_num = int(value)
        except ValueError:
            self.value_label.setText(value)
            return
        if old_num == new_num:
            self.value_label.setText(value)
            return
        self._count_anim.stop()
        self._count_anim.setStartValue(old_num)
        self._count_anim.setEndValue(new_num)
        self._count_anim.start()

    def set_trend(self, delta):
        """delta: int|float|None. None이면 비교 대상 회차가 없다는 뜻이라 아예 숨긴다
        (0 같은 값과 헷갈리지 않도록 - 실측 데이터가 없을 때 억지로 '변동없음'을
        표시하지 않는다)."""
        if delta is None:
            self.trend_label.setVisible(False)
            return
        self.trend_label.setVisible(True)
        if delta > 0:
            self.trend_label.setText(f"▲ 전 회차 대비 +{delta}")
            self.trend_label.setStyleSheet(f"color: {COLORS['danger_text']}; font-size: 11px; border:none;")
        elif delta < 0:
            self.trend_label.setText(f"▼ 전 회차 대비 {delta}")
            self.trend_label.setStyleSheet(f"color: {COLORS['success_text']}; font-size: 11px; border:none;")
        else:
            self.trend_label.setText("─ 전 회차 대비 변동 없음")
            self.trend_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; border:none;")


class DonutGauge(QWidget):
    """[UI/UX 개선] 목업(zvulnscan_design_directions)의 SVG 도넛 게이지
    (circle + stroke-dasharray)를 외부 리소스 없이 QPainter arc로 재현한다.
    percent: 0~100 또는 None(스캔 이력이 없어 계산 불가 - 회색 빈 링으로 표시,
    가짜 값을 채우지 않는다)."""
    def __init__(self, percent=None, size=44, stroke=5, parent=None):
        super().__init__(parent)
        self._percent = percent
        self._size = size
        self._stroke = stroke
        self.setFixedSize(size, size)
        # [버그 수정] HoverLiftFrame/MetricCard와 동일 - 인스턴스당 하나만 만들어
        # 재사용한다(DeleteWhenStopped로 매번 새로 만들면 다음 호출에서 크래시).
        self._fill_anim = QVariantAnimation(self)
        self._fill_anim.setEasingCurve(QEasingCurve.OutCubic)
        self._fill_anim.valueChanged.connect(self.set_percent)

    def set_percent(self, percent):
        self._percent = percent
        self.update()

    def animate_to(self, percent, duration=600):
        """[UI/UX 개선 - 인터랙션] 게이지가 즉시 스냅하지 않고 이전 값에서 새 값까지
        차오르는 애니메이션. 시작/끝 어느 한쪽이 None(데이터 없음)이면 애니메이션할
        중간값이 의미 없으므로 바로 반영한다."""
        if self._percent is None or percent is None:
            self._fill_anim.stop()
            self.set_percent(percent)
            return
        self._fill_anim.stop()
        self._fill_anim.setStartValue(float(self._percent))
        self._fill_anim.setEndValue(float(percent))
        self._fill_anim.setDuration(duration)
        self._fill_anim.start()

    def _color(self):
        if self._percent is None:
            return COLORS["text_muted"]
        if self._percent >= 80:
            return COLORS["success_text"]
        if self._percent >= 50:
            return COLORS["warning_text"]
        return COLORS["danger_text"]

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        s = self._stroke
        rect = QRectF(s / 2, s / 2, self._size - s, self._size - s)

        bg_pen = QPen(QColor(COLORS["border"]))
        bg_pen.setWidthF(s)
        bg_pen.setCapStyle(Qt.RoundCap)
        painter.setPen(bg_pen)
        painter.drawArc(rect, 0, 360 * 16)

        if self._percent is not None:
            fg_pen = QPen(QColor(self._color()))
            fg_pen.setWidthF(s)
            fg_pen.setCapStyle(Qt.RoundCap)
            painter.setPen(fg_pen)
            span = int(360 * 16 * max(0, min(100, self._percent)) / 100)
            painter.drawArc(rect, 90 * 16, -span)  # 12시 방향에서 시계방향으로 채움
        painter.end()


class SecurityLevelCard(HoverLiftFrame):
    """[UI/UX 개선] KPI 4번째 칸 - '보안수준' 도넛 게이지. db_connector.get_dashboard_trend()의
    실측 계산값을 표시한다(Excel 리포트 표지의 보안수준과 동일 산식). 스캔 이력이 없으면
    게이지를 빈 회색으로, 값은 '-'로 둔다 - 가짜 퍼센트를 채우지 않는다."""
    def __init__(self, parent=None):
        super().__init__(base_blur=16, base_y=2, alpha=22, parent=parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['surface_1']};
                border-radius: 10px;
                border-left: 4px solid {COLORS['accent']};
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 11, 14, 11)
        layout.setSpacing(4)

        label_row = QHBoxLayout()
        label_row.setSpacing(4)
        label_widget = QLabel("보안수준")
        label_widget.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px; border:none;")
        label_row.addWidget(label_widget)
        label_row.addWidget(InfoIcon(
            "KISA 중요도 가중치 기준 보안수준 - (전체점수-취약점수)/전체점수.\n"
            "Excel 리포트 표지의 보안수준과 동일한 산식으로 계산됩니다."
        ))
        label_row.addStretch()
        layout.addLayout(label_row)

        body_row = QHBoxLayout()
        body_row.setSpacing(10)
        self.value_label = QLabel("-")
        self.value_label.setStyleSheet(f"color: {COLORS['text']}; font-size: 24px; font-weight: 600; border:none;")
        body_row.addWidget(self.value_label)
        body_row.addStretch()
        self.gauge = DonutGauge()
        body_row.addWidget(self.gauge)
        layout.addLayout(body_row)

        self.trend_label = QLabel("")
        self.trend_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; border:none;")
        self.trend_label.setVisible(False)
        layout.addWidget(self.trend_label)

        # [버그 수정] 위 위젯들과 동일 - 인스턴스당 하나만 만들어 재사용한다.
        self._value_anim = QVariantAnimation(self)
        self._value_anim.setDuration(600)
        self._value_anim.setEasingCurve(QEasingCurve.OutCubic)
        self._value_anim.valueChanged.connect(lambda v: self.value_label.setText(f"{v:.1f}%"))

    def _animate_value_label(self, target):
        """DonutGauge.animate_to()와 같은 타이밍으로 퍼센트 숫자도 함께 카운트업한다."""
        try:
            old_val = float(self.value_label.text().rstrip("%"))
        except ValueError:
            self.value_label.setText(f"{target:g}%")
            return
        self._value_anim.stop()
        self._value_anim.setStartValue(old_val)
        self._value_anim.setEndValue(float(target))
        self._value_anim.start()

    def set_security_level(self, current, previous, delta):
        if current is None:
            self.value_label.setText("-")
            self.gauge.set_percent(None)
            self.trend_label.setVisible(False)
            return
        self._animate_value_label(current)
        self.gauge.animate_to(current)
        if delta is None:
            self.trend_label.setVisible(False)
        else:
            self.trend_label.setVisible(True)
            if delta > 0:
                self.trend_label.setText(f"▲ 전 회차 대비 +{delta:g}%p")
                self.trend_label.setStyleSheet(f"color: {COLORS['success_text']}; font-size: 11px; border:none;")
            elif delta < 0:
                self.trend_label.setText(f"▼ 전 회차 대비 {delta:g}%p")
                self.trend_label.setStyleSheet(f"color: {COLORS['danger_text']}; font-size: 11px; border:none;")
            else:
                self.trend_label.setText("─ 전 회차 대비 변동 없음")
                self.trend_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; border:none;")


class InfoCard(QFrame):
    """카드형 패널 공통 컨테이너 (Scan configuration, Assets 테이블 wrapper 등에서 사용)."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['surface_2']};
                border: 1px solid {COLORS['border']};
                border-radius: 12px;
            }}
        """)
        _apply_card_shadow(self)


# ----------------------------------------------------------------------
# Scan configuration 카드
# ----------------------------------------------------------------------
class ScanConfigCard(InfoCard):
    """
    main_window.py는 이 카드의 위젯들을 기존 속성명으로 alias해서 그대로 쓴다
    (예: self.ip_input = self.scan_config.target_input). 버튼도 Signal 대신
    QPushButton을 직접 노출해서 main_window.py가 기존 방식대로 .clicked.connect(...)한다.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(22, 18, 22, 18)
        outer.setSpacing(3)

        title = QLabel(f"<span style='color:{COLORS['accent']};'>&#9679;</span> Scan configuration")
        title.setStyleSheet(f"font-size: 15px; font-weight: 600; color: {COLORS['text']}; border:none;")
        outer.addWidget(title)

        subtitle = QLabel("Set the target range, how it's scanned, and how much load it puts on the network.")
        subtitle.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; border:none;")
        outer.addWidget(subtitle)
        outer.addSpacing(10)

        # --- 1행: Target range (전체 폭) ---
        outer.addWidget(LabelWithHelp("Target range", "IP, 범위(10.0.0.1-50), 또는 CIDR(10.0.0.0/24). 'Import'로 CSV/Excel 자산목록에서 채울 수 있습니다."))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. 192.168.1.1 or 192.168.1.0/24")
        target_row = QHBoxLayout()
        target_row.setContentsMargins(0, 0, 0, 0)
        target_row.addWidget(self.target_input)
        self.import_btn = QPushButton("Import")
        self.import_btn.setFixedWidth(72)
        target_row.addWidget(self.import_btn)
        outer.addLayout(target_row)
        outer.addSpacing(8)

        # --- 2행: Scan mode / Credentials (좁은 창에서도 겹치지 않게 2열로만 구성) ---
        row1 = QGridLayout()
        row1.setHorizontalSpacing(18)
        row1.setVerticalSpacing(4)

        # Scan mode: 인덱스 순서는 기존 워커 분기(0=Fast,1=Custom,2=Full)와 맞춘다
        self.scan_mode_combo = QComboBox()
        self.scan_mode_combo.addItems(["Fast scan", "Custom", "Full scan (1-65535)"])
        mode_col = QVBoxLayout()
        mode_col.setContentsMargins(0, 0, 0, 0)
        mode_col.addWidget(self.scan_mode_combo)
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Custom ports (80,443,8000-8100)")
        self.port_input.setEnabled(False)
        mode_col.addWidget(self.port_input)
        mode_wrap = QWidget()
        mode_wrap.setLayout(mode_col)
        row1.addWidget(LabelWithHelp("Scan mode", "Fast: 주요 포트만 빠르게 확인 / Custom: 직접 지정한 포트만 확인 / Full: 1~65535 전체 확인(느림)"), 0, 0)
        row1.addWidget(mode_wrap, 1, 0)

        # Credentials: 실제 SSH/WinRM 접속에 쓰이는 값이라 드롭다운이 아니라 직접 입력 유지
        cred_col = QVBoxLayout()
        cred_col.setContentsMargins(0, 0, 0, 0)
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("User")
        cred_col.addWidget(self.user_input)
        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("Password")
        self.pw_input.setEchoMode(QLineEdit.Password)
        cred_col.addWidget(self.pw_input)

        # [DB 전용 계정] SSH/WinRM 계정과 DB(MySQL/PostgreSQL/MSSQL) 계정이 다른 경우가 실무에서
        # 흔하므로(예: SSH는 개인 계정, DB는 DBA가 관리하는 별도 감사 계정), 체크할 때만
        # 별도 입력칸을 보여준다. 비워두면 지금까지와 동일하게 위 SSH/WinRM 계정을 그대로 쓴다.
        self.db_cred_diff_check = QCheckBox("DB 계정이 SSH/WinRM 계정과 다름")
        cred_col.addWidget(self.db_cred_diff_check)

        self.db_user_input = QLineEdit()
        self.db_user_input.setPlaceholderText("DB User")
        self.db_user_input.setVisible(False)
        cred_col.addWidget(self.db_user_input)
        self.db_pw_input = QLineEdit()
        self.db_pw_input.setPlaceholderText("DB Password")
        self.db_pw_input.setEchoMode(QLineEdit.Password)
        self.db_pw_input.setVisible(False)
        cred_col.addWidget(self.db_pw_input)

        # [Oracle 서비스명] host+port만으론 접속이 안 되고 서비스명(Service Name/SID)이
        # 반드시 필요하다 - MySQL/PostgreSQL/MSSQL과 다른 지점. DB 계정 공유 여부와
        # 무관하게 필요해서 위 체크박스 토글 대상에는 안 넣고 항상 노출한다.
        self.oracle_service_input = QLineEdit()
        self.oracle_service_input.setPlaceholderText("Oracle Service Name (선택, 비우면 ORCL 시도)")
        self.oracle_service_input.setToolTip(
            "대상에 Oracle DB가 있을 경우에만 사용됩니다.\n"
            "비워두면 가장 흔한 기본값(ORCL)으로 접속을 시도하며, 설치 환경마다 실제 값이 다를 수 있습니다."
        )
        cred_col.addWidget(self.oracle_service_input)

        def _toggle_db_cred_inputs(checked):
            self.db_user_input.setVisible(checked)
            self.db_pw_input.setVisible(checked)
        self.db_cred_diff_check.toggled.connect(_toggle_db_cred_inputs)

        cred_wrap = QWidget()
        cred_wrap.setLayout(cred_col)
        row1.addWidget(LabelWithHelp("Credentials", "딥 진단(SSH/WinRM)에 필요합니다. 없으면 포트·배너만 점검합니다.\nDB(MySQL/PostgreSQL/MSSQL) 계정이 따로 있으면 아래 체크박스로 별도 입력할 수 있습니다."), 0, 1)
        row1.addWidget(cred_wrap, 1, 1)

        row1.setColumnStretch(0, 1)
        row1.setColumnStretch(1, 1)
        outer.addLayout(row1)

        outer.addSpacing(10)
        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet(f"color: {COLORS['border']}; background-color: {COLORS['border']}; max-height: 1px;")
        outer.addWidget(divider)
        outer.addSpacing(10)

        # --- 2행: Concurrency 슬라이더 ---
        conc_header = QHBoxLayout()
        conc_header.addWidget(LabelWithHelp("Concurrency", "동시에 점검할 호스트 수. 노후·OT 장비는 낮게 설정하세요."))
        conc_header.addStretch()
        self.concurrency_value_label = QLabel("3 hosts")
        self.concurrency_value_label.setStyleSheet(f"font-weight: 500; color: {COLORS['text']};")
        conc_header.addWidget(self.concurrency_value_label)
        outer.addLayout(conc_header)

        self.concurrency_slider = QSlider(Qt.Horizontal)
        self.concurrency_slider.setRange(1, 30)
        self.concurrency_slider.setValue(3)
        self.concurrency_slider.valueChanged.connect(
            lambda v: self.concurrency_value_label.setText(f"{v} hosts")
        )
        outer.addWidget(self.concurrency_slider)

        hint = QLabel("Lower = gentler on the network, slower scan. Recommended: 1-3 for OT networks.")
        hint.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; border:none;")
        outer.addWidget(hint)
        outer.addSpacing(10)

        divider2 = QFrame()
        divider2.setFrameShape(QFrame.HLine)
        divider2.setStyleSheet(f"color: {COLORS['border']}; background-color: {COLORS['border']}; max-height: 1px;")
        outer.addWidget(divider2)
        outer.addSpacing(10)

        # --- 3행: 체크박스 + 액션 버튼 3개 (Discovery Only / Start Audit / Stop) ---
        bottom_row = QHBoxLayout()

        self.ot_mode_check = QCheckBox("OT / low-rate mode")
        self.ot_mode_check.setChecked(True)  # 안전 우선 기본값
        self.ot_mode_check.setToolTip("장비 응답이 느리면 자동으로 더 느리게 조절합니다. 레거시/OT 장비 권장.")

        self.demo_mode_check = QCheckBox("Demo mode")
        self.demo_mode_check.setToolTip("체크 시에만 데모용 가짜 데이터를 사용합니다. 실제 현장 진단에서는 반드시 꺼두세요 (기본값 OFF).")
        self.demo_mode_check.setStyleSheet(f"color: {COLORS['warning_text']}; font-weight: bold;")

        bottom_row.addWidget(self.ot_mode_check)
        bottom_row.addSpacing(12)
        bottom_row.addWidget(self.demo_mode_check)
        bottom_row.addStretch()

        secondary_btn_style = f"""
            QPushButton {{
                background-color: {COLORS['surface_1']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 12px;
            }}
            QPushButton:hover {{ background-color: {COLORS['accent_bg']}; }}
            QPushButton:disabled {{ color: {COLORS['text_muted']}; }}
        """

        self.discovery_btn = QPushButton("Discovery Only")
        self.discovery_btn.setCursor(Qt.PointingHandCursor)
        self.discovery_btn.setToolTip("계정 정보 없이 자산 탐지만 수행합니다. KISA 딥 진단은 수행하지 않습니다.")
        self.discovery_btn.setStyleSheet(secondary_btn_style)
        bottom_row.addWidget(self.discovery_btn)

        self.audit_btn = QPushButton("Start Audit")
        self.audit_btn.setCursor(Qt.PointingHandCursor)
        self.audit_btn.setToolTip("계정 정보로 접속해 KISA 룰셋 기반 딥 진단을 수행합니다.")
        self.audit_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['accent']};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 8px 20px;
                font-size: 12px;
            }}
            QPushButton:hover {{ background-color: #2860D6; }}
            QPushButton:disabled {{ background-color: {COLORS['border']}; color: {COLORS['text_muted']}; }}
        """)
        bottom_row.addWidget(self.audit_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setCursor(Qt.PointingHandCursor)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['surface_2']};
                color: {COLORS['danger_text']};
                border: 1px solid {COLORS['danger_bg']};
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 12px;
            }}
            QPushButton:hover {{ background-color: {COLORS['danger_bg']}; }}
            QPushButton:disabled {{ color: {COLORS['text_muted']}; border-color: {COLORS['border']}; }}
        """)
        bottom_row.addWidget(self.stop_btn)

        outer.addLayout(bottom_row)


# ----------------------------------------------------------------------
# 지표 카드 4개
# ----------------------------------------------------------------------
class MetricsRow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        grid = QGridLayout(self)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(10)

        # [디자인 목업 일치] zvulnscan_design_directions 방향 C의 한글 라벨을 그대로 사용.
        self.assets_card = MetricCard("스캔된 자산", "0", icon_kind="asset")
        self.critical_card = MetricCard("취약 항목", "0", tone="danger", icon_kind="warning")
        self.partial_card = MetricCard("부분만족", "0", tone="warning", icon_kind="info")
        # [UI/UX 개선] 목업의 4번째 칸은 '접속 실패' 숫자가 아니라 '보안수준' 도넛
        # 게이지다 - db_connector.get_dashboard_trend()의 실측 계산값으로 채운다.
        self.security_card = SecurityLevelCard()

        # [버그 수정] 목업(zvulnscan_design_directions, .kpis { grid-template-columns:
        # repeat(4, 1fr) })은 1행 4열인데 2행 2열로 잘못 배치돼 있었다.
        grid.addWidget(self.assets_card, 0, 0)
        grid.addWidget(self.critical_card, 0, 1)
        grid.addWidget(self.partial_card, 0, 2)
        grid.addWidget(self.security_card, 0, 3)
        for col in range(4):
            grid.setColumnStretch(col, 1)

        # 대시보드 갱신 로직에서 key로 바로 찾아 쓸 수 있게 (보안수준 게이지는 별도 위젯이라
        # set_value()로 채울 수 없어 self.cards에는 넣지 않고 set_security_level()로 따로 갱신한다)
        self.cards = {
            "assets_scanned": self.assets_card,
            "critical_findings": self.critical_card,
            "partial_compliance": self.partial_card,
        }

    def update_counts(self, metrics: dict):
        for key, card in self.cards.items():
            card.set_value(str(metrics.get(key, 0)))

    def update_trend(self, trend: dict):
        """trend: db_connector.get_dashboard_trend()의 반환값."""
        self.security_card.set_security_level(**trend.get("security_level", {}))
        self.critical_card.set_trend(trend.get("critical_findings", {}).get("delta"))
        self.partial_card.set_trend(trend.get("partial_compliance", {}).get("delta"))


# ----------------------------------------------------------------------
# [UI/UX 개선] 최근 활동 카드 - 목업의 "최근 활동"을 그대로 반영. KPI 카드처럼
# 가로 정렬된 블록이 아니라, 세션 하나당 행 하나인 개별 리스트다.
# ----------------------------------------------------------------------
class _ClickableRow(QFrame):
    """[UI/UX 개선 - 드릴다운] '최근 활동' 행 하나. 클릭하면 clicked(session_id)를
    쏘고, 호버 시 배경색으로만 가볍게 반응한다(KPI 카드처럼 그림자 애니메이션까지
    쓰면 리스트에서는 오히려 산만해서 배경색 전환만 사용)."""
    clicked = Signal(str)

    def __init__(self, session_id: str, parent=None):
        super().__init__(parent)
        self._session_id = session_id
        self.setCursor(Qt.PointingHandCursor)
        self._base_style = ""
        self._hover_style = f"background-color: {COLORS['surface_1']};"

    def set_base_style(self, style: str):
        self._base_style = style
        self.setStyleSheet(self._base_style)

    def mousePressEvent(self, event):
        self.clicked.emit(self._session_id)
        super().mousePressEvent(event)

    def enterEvent(self, event):
        self.setStyleSheet(self._base_style + self._hover_style)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setStyleSheet(self._base_style)
        super().leaveEvent(event)


class RecentActivityCard(InfoCard):
    # [UI/UX 개선 - 드릴다운] 세션 행 클릭 시 그 세션의 진단 결과만 자산 탭에서
    # 보여주기 위해 main_window.py가 구독하는 시그널.
    session_clicked = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header_row = QHBoxLayout()
        header_row.setContentsMargins(18, 12, 18, 8)
        title = QLabel("최근 활동")
        title.setStyleSheet(f"font-size: 14px; font-weight: 600; color: {COLORS['text']}; border:none;")
        header_row.addWidget(title)
        header_row.addStretch()
        outer.addLayout(header_row)

        self.rows_layout = QVBoxLayout()
        self.rows_layout.setContentsMargins(0, 0, 0, 6)
        self.rows_layout.setSpacing(0)
        outer.addLayout(self.rows_layout)

        self._empty_label = QLabel("아직 스캔 이력이 없습니다.")
        self._empty_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px; border:none; padding: 4px 18px 12px;")
        self.rows_layout.addWidget(self._empty_label)

    def set_sessions(self, sessions):
        """sessions: [(session_id, operator, started_at, asset_count), ...] (최신순)."""
        while self.rows_layout.count():
            item = self.rows_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        if not sessions:
            self._empty_label = QLabel("아직 스캔 이력이 없습니다.")
            self._empty_label.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 12px; border:none; padding: 4px 18px 12px;")
            self.rows_layout.addWidget(self._empty_label)
            return

        for i, (session_id, operator, started_at, asset_count) in enumerate(sessions):
            row = _ClickableRow(session_id)
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(18, 8, 18, 8)
            row_layout.setSpacing(10)
            row.set_base_style(f"border-top: 1px solid {COLORS['border']};" if i > 0 else "")
            row.clicked.connect(self.session_clicked.emit)

            dot = QLabel()
            dot.setFixedSize(8, 8)
            dot.setStyleSheet(f"background-color: {COLORS['accent']}; border-radius: 4px; border:none;")
            row_layout.addWidget(dot, 0, Qt.AlignVCenter)

            main_col = QVBoxLayout()
            main_col.setSpacing(2)
            title_lbl = QLabel(session_id or "-")
            title_lbl.setStyleSheet(f"color: {COLORS['text']}; font-size: 12.5px; font-weight: 600; border:none;")
            main_col.addWidget(title_lbl)
            sub_lbl = QLabel(operator or "담당자 미기록")
            sub_lbl.setStyleSheet(f"color: {COLORS['text_muted']}; font-size: 11px; border:none;")
            main_col.addWidget(sub_lbl)
            row_layout.addLayout(main_col, 1)

            stat_lbl = QLabel(f"{asset_count}대 · {started_at or '-'}")
            stat_lbl.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 11.5px; border:none;")
            stat_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            row_layout.addWidget(stat_lbl)

            self.rows_layout.addWidget(row)


# ----------------------------------------------------------------------
# Assets 테이블 (범례 + 상태 배지)
# ----------------------------------------------------------------------
class AssetsTableCard(InfoCard):
    HEADERS = ["Host", "OS", "KISA code", "Status", "Risk"]

    def __init__(self, parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header_row = QHBoxLayout()
        header_row.setContentsMargins(20, 16, 20, 4)
        title = QLabel(f"<span style='color:{COLORS['accent']};'>&#9679;</span> Assets")
        title.setStyleSheet(f"font-size: 14px; font-weight: 600; color: {COLORS['text']}; border:none;")
        header_row.addWidget(title)
        header_row.addStretch()
        # main_window.py가 여기에 Waiver/Expert mode/Refresh 버튼을 추가한다
        self.actions_layout = QHBoxLayout()
        header_row.addLayout(self.actions_layout)
        outer.addLayout(header_row)

        legend_row = QHBoxLayout()
        legend_row.setContentsMargins(20, 0, 20, 10)
        for status_key in ["VULNERABLE", "PARTIAL", "SAFE", "MANUAL"]:
            bg, fg, label = STATUS_STYLE[status_key]
            legend_row.addWidget(LegendDot(fg, label))
            legend_row.addSpacing(10)
        legend_row.addStretch()
        outer.addLayout(legend_row)

        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.verticalHeader().hide()
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setDefaultSectionSize(38)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.setMinimumHeight(240)
        self.table.setStyleSheet(f"""
            QTableWidget {{ border: none; background-color: {COLORS['surface_2']}; }}
            QHeaderView::section {{
                background-color: {COLORS['surface_2']};
                color: {COLORS['text_secondary']};
                border: none;
                border-bottom: 1px solid {COLORS['border']};
                padding: 6px 8px;
                font-size: 11px;
            }}
            QTableWidget::item {{ padding: 3px 5px; color: {COLORS['text']}; font-size: 12px; }}
            QTableWidget::item:selected {{ background-color: {COLORS['accent_bg']}; color: {COLORS['text']}; }}
        """)
        outer.addWidget(self.table)

    def add_row(self, host: str, os_type: str, kisa_code: str, status: str, risk: str):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(host))
        self.table.setItem(row, 1, QTableWidgetItem(os_type))
        self.table.setItem(row, 2, QTableWidgetItem(kisa_code))

        badge = StatusBadge(status)
        self.table.setCellWidget(row, 3, badge)

        risk_item = QTableWidgetItem(risk or "")
        risk_item.setForeground(QColor(RISK_TEXT_COLOR.get(risk, COLORS["text_secondary"])))
        risk_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.table.setItem(row, 4, risk_item)

    def clear_rows(self):
        self.table.setRowCount(0)
