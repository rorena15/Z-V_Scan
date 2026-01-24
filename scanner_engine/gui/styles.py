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
QWidget { color: #d4d4d4; font-size: 10pt; font-family: 'Segoe UI', sans-serif; }
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
QPushButton:hover { background-color: #4a4a4a; border-color: #007acc; }
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
"""