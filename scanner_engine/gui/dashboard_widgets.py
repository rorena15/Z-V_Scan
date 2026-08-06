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
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor


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


def set_theme(theme_name):
    """main_window.py가 위젯을 만들기 "전"에 한 번 호출한다 (theme_name: 'light' 또는 'dark')."""
    COLORS.clear()
    COLORS.update(DARK_COLORS if theme_name == "dark" else LIGHT_COLORS)
    _rebuild_derived_styles()


_rebuild_derived_styles()


def _apply_card_shadow(widget, blur=22, y_offset=3, alpha=28):
    """[미니멀 인상 완화] 카드에 은은한 그림자를 줘서 배경과 구분되는 입체감을 준다."""
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setOffset(0, y_offset)
    effect.setColor(QColor(0, 0, 0, alpha))
    widget.setGraphicsEffect(effect)


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


class MetricCard(QFrame):
    """지표 카드 (Assets scanned / Critical findings 등). tone: 'default'|'danger'|'warning'."""
    def __init__(self, label: str, value: str, tone: str = "default",
                 tooltip_text: str = None, parent=None):
        super().__init__(parent)
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
        _apply_card_shadow(self, blur=16, y_offset=2, alpha=22)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

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
        layout.addLayout(label_row)

        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"color: {text_map[tone]}; font-size: 24px; font-weight: 600; border:none;")
        layout.addWidget(self.value_label)

    def set_value(self, value: str):
        self.value_label.setText(value)


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
        grid.setSpacing(12)

        self.assets_card = MetricCard("Assets scanned", "0")
        self.critical_card = MetricCard("Critical findings", "0", tone="danger")
        self.partial_card = MetricCard("Partial compliance", "0", tone="warning")
        self.conn_error_card = MetricCard(
            "Connection errors", "0",
            tooltip_text="접속 실패·인증 실패 - 실제 점검이 안 된 항목입니다. 수동으로 확인이 필요합니다."
        )

        grid.addWidget(self.assets_card, 0, 0)
        grid.addWidget(self.critical_card, 0, 1)
        grid.addWidget(self.partial_card, 1, 0)
        grid.addWidget(self.conn_error_card, 1, 1)

        # 대시보드 갱신 로직에서 key로 바로 찾아 쓸 수 있게
        self.cards = {
            "assets_scanned": self.assets_card,
            "critical_findings": self.critical_card,
            "partial_compliance": self.partial_card,
            "connection_errors": self.conn_error_card,
        }

    def update_counts(self, metrics: dict):
        for key, card in self.cards.items():
            card.set_value(str(metrics.get(key, 0)))


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
