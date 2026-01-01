# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
STYLESHEET = """
QMainWindow { background-color: #1e1e1e; }
QWidget { color: #e0e0e0; font-family: 'Segoe UI', sans-serif; font-size: 11pt; }
QGroupBox { 
    border: 1px solid #3e3e3e; 
    border-radius: 8px; 
    margin-top: 20px; 
    background-color: #252526; 
    font-weight: bold; 
    color: #007acc; 
}
QGroupBox::title { subcontrol-origin: margin; left: 15px; padding: 0 5px; }
QLineEdit { 
    background-color: #333333; 
    border: 1px solid #444444; 
    border-radius: 4px; 
    padding: 8px; 
    color: #ffffff; 
}
QLineEdit:focus { border: 1px solid #007acc; }
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
QPushButton#ClearBtn { 
    padding: 4px 10px; 
    font-size: 9pt; 
    background-color: #444; 
    border: 1px solid #666; 
}
QPushButton#ClearBtn:hover { background-color: #c0392b; border-color: #e74c3c; }
QTableWidget { 
    background-color: #252526; 
    alternate-background-color: #2d2d30;
    border: 1px solid #3e3e3e; 
    gridline-color: #3e3e3e; 
    color: #cccccc; 
}
QTableWidget::item {
    padding: 4px;
    border-bottom: 0px;
}
QTableWidget::item:selected {
    background-color: #094771;
    color: white;
}
QHeaderView::section { 
    background-color: #333333; 
    padding: 6px; 
    border: 1px solid #3e3e3e; 
    color: #e0e0e0; 
    font-weight: bold; 
}
QTextEdit { 
    background-color: #1e1e1e; 
    border: 1px solid #3e3e3e; 
    color: #00ff00; 
    font-family: 'Consolas', monospace; 
    font-size: 9pt; 
}
QProgressBar { 
    border: 1px solid #3e3e3e; 
    border-radius: 5px; 
    text-align: center; 
    background-color: #252526; 
    color: white; 
}
QProgressBar::chunk { background-color: #007acc; border-radius: 4px; }

QSplitter::handle { background-color: #3e3e3e; }

QComboBox{
    background-color: #333333;
}
QComboBox QAbstractItemView {
    background-color: #333333;
    color: #ffffff;
    selection-background-color: #007acc;
    selection-color: #ffffff;
    border: 1px solid #3e3e3e;
}
QMessageBox {
    background-color: #252526;
    color: #e0e0e0;
    border: 1px solid #3e3e3e;
}
QMessageBox QLabel {
    color: #e0e0e0; /* 메시지 텍스트 색상 */
    font-weight: normal;
}
QInputDialog {
    background-color: #1e1e1e; 
    border: 1px solid #3e3e3e; 
    color: #00ff00; 
    font-family: 'Consolas', monospace; 
    font-size: 9pt; 
}
"""