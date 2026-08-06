# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
STYLESHEET = """
/* [공통] 윈도우 및 폰트 */
QMainWindow { background-color: #1e1e1e; }
QWidget { color: #d4d4d4; font-size: 10pt; font-family: 'Pretendard', '맑은 고딕', 'Malgun Gothic', 'Segoe UI', sans-serif; }
QToolTip { color: #ffffff; background-color: #2b2b2b; border: 1px solid #767676; }

/* [입력창] QLineEdit */
QLineEdit {
    background-color: #2d2d30;
    color: #ffffff;
    border: 1px solid #3e3e42;
    border-radius: 4px;
    padding: 6px;
}
QLineEdit:focus { border: 1px solid #555555; background-color: #1e1e1e; }
QLineEdit:disabled { background-color: #333333; color: #888888; }

/* [콤보박스] QComboBox */
QComboBox {
    background-color: #2d2d30;
    border: 1px solid #3e3e42;
    border-radius: 4px;
    padding: 5px;
    color: #ffffff;
}
QComboBox::drop-down { border: none; }
QComboBox::down-arrow { image: none; border-left: 2px solid #555; width: 0; height: 0; }
QComboBox QAbstractItemView {
    background-color: #2d2d30;
    color: #ffffff;
    border: 1px solid #3e3e42;
    selection-background-color: #3e3e42;
    selection-color: #ffffff;
}

/* [버튼] 기본 스타일 */
QPushButton {
    background-color: #3a3a3a;
    border: 1px solid #555555;
    border-radius: 6px;
    padding: 10px 15px;
    color: #ffffff;
    font-weight: bold;
}
QPushButton:hover { background-color: #4a4a4a; border-color: #5B8DEF; }
QPushButton:pressed { background-color: #2a2a2a; }
QPushButton:disabled { background-color: #252526; color: #666666; border-color: #333333; }

/* [특수 버튼] Clear 버튼 등 작은 버튼 */
QPushButton#ClearBtn { 
    padding: 4px 10px; 
    font-size: 9pt; 
    background-color: #444; 
    border: 1px solid #666; 
}
QPushButton#ClearBtn:hover { background-color: #c0392b; border-color: #e74c3c; }

/* [그룹박스] 설정 영역 */
QGroupBox { 
    border: 1px solid #333; 
    border-radius: 6px; 
    margin-top: 10px; 
    background-color: #252526; 
    color: #ddd; 
    font-weight: bold;
    padding-top: 15px;
}
QGroupBox::title { subcontrol-origin: margin; left: 15px; padding: 0 5px; }

/* [테이블] 결과 목록 */
QTableWidget { 
    background-color: #1e1e1e; 
    gridline-color: #333; 
    border: 1px solid #444; 
    border-radius: 4px; 
    alternate-background-color: #252526;
}
QHeaderView::section { 
    background-color: #252526; 
    color: #ccc; 
    padding: 8px; 
    border: none; 
    border-bottom: 1px solid #444; 
    font-weight: bold; 
}
QTableWidget::item { padding: 5px; color: #ddd; }
QTableWidget::item:selected { 
    background-color: #37373d; 
    color: white; 
    border-left: 2px solid #ff5555; 
}
QTableWidget::item:hover { background-color: #2a2a2e; }

/* [로그 창] */
QTextEdit {
    background-color: #101010;
    color: #cccccc;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 9pt;
    border: 1px solid #444;
    border-radius: 4px;
    padding: 5px;
}

/* [툴바] */
QToolBar { background: #252526; border-bottom: 1px solid #333; spacing: 10px; padding: 5px; }
QToolButton { color: #cccccc; background: transparent; padding: 6px; border-radius: 4px; font-weight: bold; }
QToolButton:hover { background: #3e3e42; color: white; }
QToolButton:disabled { color: #555; }

/* [알림창/다이얼로그] */
QMessageBox, QInputDialog {
    background-color: #252526;
    color: #d4d4d4;
    border: 1px solid #3e3e3e;
}
QMessageBox QLabel, QInputDialog QLabel {
    color: #d4d4d4;
    font-weight: normal;
}
QMessageBox QPushButton, QInputDialog QPushButton {
    background-color: #3e3e42;
    color: white;
    border: 1px solid #555;
    border-radius: 4px;
    padding: 6px 20px;
    min-width: 60px;
}
QMessageBox QPushButton:hover, QInputDialog QPushButton:hover {
    background-color: #4e4e52;
    border-color: #777;
}

/* [상태바 & 프로그레스바] */
QSplitter::handle { background-color: #333; }
QProgressBar {
    background: #1e1e1e;
    border: 1px solid #444;
    border-radius: 3px;
    text-align: center;
    color: white;
}
QProgressBar::chunk { background: #888; }

/* [Phase 3: UI 재구성] 대시보드 카드 스크롤 영역 - 기본값은 팔레트 기반 불투명 배경이라
   QMainWindow의 어두운 배경과 분리되어 보이므로 명시적으로 투명 처리 */
QScrollArea { background: transparent; border: none; }
QScrollArea > QWidget > QWidget { background: transparent; }
"""

# [Phase 3: 설정 페이지 - 테마] 라이트 테마
# [UI/UX 개선 - "신뢰할 수 있는 작업대" 방향] dashboard_widgets.py의 LIGHT_COLORS와
# 같은 팔레트(쿨톤 배경 #F5F7FA, 파랑 액센트 #2E6BE6)로 맞춤 - 이 파일은 그
# 토큰 dict를 직접 import하지 않는 독립된 전역 QSS라, 색상 값을 나란히 맞춰
# 관리한다(dashboard_widgets.LIGHT_COLORS를 바꾸면 이 블록도 같이 봐야 함).
LIGHT_STYLESHEET = """
QMainWindow { background-color: #F5F7FA; }
QWidget { color: #1B2430; font-size: 10pt; font-family: 'Pretendard', '맑은 고딕', 'Malgun Gothic', 'Segoe UI', sans-serif; }
QToolTip { color: #1B2430; background-color: #FFFFFF; border: 1px solid #E3E7EE; }

QLineEdit {
    background-color: #FFFFFF;
    color: #1B2430;
    border: 1px solid #E3E7EE;
    border-radius: 8px;
    padding: 7px 9px;
}
QLineEdit:focus { border: 1px solid #2E6BE6; background-color: #FFFFFF; }
QLineEdit:disabled { background-color: #EEF1F5; color: #8B94A3; }

QComboBox {
    background-color: #FFFFFF;
    border: 1px solid #E3E7EE;
    border-radius: 8px;
    padding: 5px;
    color: #1B2430;
}
QComboBox::drop-down { border: none; }
QComboBox::down-arrow { image: none; border-left: 2px solid #5B6675; width: 0; height: 0; }
QComboBox QAbstractItemView {
    background-color: #FFFFFF;
    color: #1B2430;
    border: 1px solid #E3E7EE;
    selection-background-color: #E8EFFE;
    selection-color: #1B2430;
}

/* [주의] 이건 앱 전체 모든 QPushButton에 적용되는 전역 규칙이다(다이얼로그
   취소/확인, DB Manager, Waiver/Expert 버튼 등 전부 포함) - 그래서 액센트
   블루를 여기 전역으로 쓰면 화면마다 파란 버튼이 난립해 주/보조 액션 구분이
   사라진다. 중립 톤을 기본으로 두고, 특정 버튼만 강조하고 싶으면 ScanConfigCard의
   스캔 시작 버튼처럼 objectName으로 별도 선택자를 추가한다(#ClearBtn 패턴 참고). */
QPushButton {
    background-color: #EEF1F5;
    border: 1px solid #E3E7EE;
    border-radius: 8px;
    padding: 10px 15px;
    color: #1B2430;
    font-weight: 600;
}
QPushButton:hover { background-color: #E3E7EE; border-color: #C7D0DC; }
QPushButton:pressed { background-color: #D5DBE5; }
QPushButton:disabled { background-color: #F5F7FA; color: #8B94A3; border-color: #E3E7EE; }

QPushButton#ClearBtn {
    padding: 4px 10px;
    font-size: 9pt;
    background-color: #EEF1F5;
    color: #1B2430;
    border: 1px solid #E3E7EE;
}
QPushButton#ClearBtn:hover { background-color: #C0271F; color: white; border-color: #C0271F; }

QGroupBox {
    border: 1px solid #E3E7EE;
    border-radius: 10px;
    margin-top: 10px;
    background-color: #FFFFFF;
    color: #1B2430;
    font-weight: 600;
    padding-top: 15px;
}
QGroupBox::title { subcontrol-origin: margin; left: 15px; padding: 0 5px; }

QTableWidget {
    background-color: #FFFFFF;
    gridline-color: #E3E7EE;
    border: 1px solid #E3E7EE;
    border-radius: 8px;
    alternate-background-color: #F5F7FA;
}
QHeaderView::section {
    background-color: #F5F7FA;
    color: #5B6675;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #E3E7EE;
    font-weight: 600;
}
QTableWidget::item { padding: 5px; color: #1B2430; }
QTableWidget::item:selected {
    background-color: #E8EFFE;
    color: #1B2430;
    border-left: 2px solid #2E6BE6;
}
QTableWidget::item:hover { background-color: #F2F6FE; }

QTextEdit {
    background-color: #FFFFFF;
    color: #1B2430;
    font-family: Consolas, 'Courier New', monospace;
    font-size: 9pt;
    border: 1px solid #E3E7EE;
    border-radius: 8px;
    padding: 5px;
}

QToolBar { background: #eaeaea; border-bottom: 1px solid #c0c0c0; spacing: 10px; padding: 5px; }
QToolButton { color: #1e1e1e; background: transparent; padding: 6px; border-radius: 4px; font-weight: bold; }
QToolButton:hover { background: #d8d8d8; color: #000; }
QToolButton:disabled { color: #aaa; }

QMessageBox, QInputDialog {
    background-color: #f3f3f3;
    color: #1e1e1e;
    border: 1px solid #c0c0c0;
}
QMessageBox QLabel, QInputDialog QLabel {
    color: #1e1e1e;
    font-weight: normal;
}
QMessageBox QPushButton, QInputDialog QPushButton {
    background-color: #e8e8e8;
    color: #1e1e1e;
    border: 1px solid #b0b0b0;
    border-radius: 4px;
    padding: 6px 20px;
    min-width: 60px;
}
QMessageBox QPushButton:hover, QInputDialog QPushButton:hover {
    background-color: #d8d8d8;
    border-color: #999;
}

QSplitter::handle { background-color: #d0d0d0; }
QProgressBar {
    background: #ffffff;
    border: 1px solid #c0c0c0;
    border-radius: 3px;
    text-align: center;
    color: #1e1e1e;
}
QProgressBar::chunk { background: #5B8DEF; }

/* [Phase 3: UI 재구성] 대시보드 카드 스크롤 영역 - 다크 테마와 동일한 이유로 투명 처리 */
QScrollArea { background: transparent; border: none; }
QScrollArea > QWidget > QWidget { background: transparent; }
"""
