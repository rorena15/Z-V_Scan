# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[자산평가] 컨설턴트 결과보고서(별첨 xx.xlsm '점검대상' 시트)의 자산평가 항목
(용도/부서/담당자 + C/I/A -> 등급)을 Z-VulnScan DB에 입력하는 다이얼로그.

DB Manager(gui/db_manager.py)와 별개 다이얼로그로 둔다 - 자산평가는 스캔이
채우는 값이 아니라 사람이 입력하는 값이고(재스캔해도 덮어써지면 안 됨),
DB Manager의 "수정 즉시 반영" 셀 편집 패턴만 그대로 재사용한다.
"""
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QLabel, QAbstractItemView
)
from PySide6.QtCore import Qt

from utils.db_connector import DBConnector

# 컬럼: ID(숨김용) / IP / Hostname / 용도 / 부서 / 담당자 / C / I / A / 등급(읽기전용)
COL_IP, COL_HOST, COL_PURPOSE, COL_DEPT, COL_OWNER, COL_C, COL_I, COL_A, COL_GRADE = range(9)


class AssetAssessmentDialog(QDialog):
    def __init__(self, db_connector, parent=None):
        super().__init__(parent)
        self.setWindowTitle("자산평가 (Asset Assessment)")
        self.resize(860, 560)
        self.db = db_connector

        layout = QVBoxLayout(self)

        info = QLabel(
            "여기서 입력한 용도/부서/담당자/C·I·A는 Excel 리포트의 '점검대상' 및 호스트별 상세 "
            "시트에 그대로 반영됩니다. C/I/A(기밀성/무결성/가용성)는 1~3점으로 입력하면 등급이 "
            "자동 계산됩니다(합산 7 이상=상, 5 이상=중, 3~4=하)."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(
            ["IP", "Hostname", "용도", "부서", "담당자", "C", "I", "A", "등급"]
        )
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        header.setSectionResizeMode(COL_IP, QHeaderView.ResizeToContents)
        for c in (COL_C, COL_I, COL_A, COL_GRADE):
            header.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.cellChanged.connect(self._on_cell_changed)
        layout.addWidget(self.table)

        btn_row = QHBoxLayout()
        btn_refresh = QPushButton("새로고침")
        btn_refresh.clicked.connect(self.load_data)
        btn_row.addWidget(btn_refresh)
        btn_row.addStretch()
        btn_close = QPushButton("닫기")
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)
        layout.addLayout(btn_row)

        self.load_data()

    # ------------------------------------------------------------------
    def load_data(self):
        self.table.blockSignals(True)
        self.table.setRowCount(0)
        rows = self.db.get_asset_assessment_list()
        for row_idx, (asset_id, ip, hostname, purpose, department, owner, c, i, a) in enumerate(rows):
            self.table.insertRow(row_idx)
            values = [ip, hostname or "", purpose or "", department or "", owner or "",
                      c, i, a, DBConnector.compute_asset_grade(c, i, a)]
            for col_idx, val in enumerate(values):
                item = QTableWidgetItem("" if val is None else str(val))
                if col_idx == COL_IP:
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    item.setData(Qt.UserRole, asset_id)
                elif col_idx == COL_GRADE:
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.table.setItem(row_idx, col_idx, item)
        self.table.blockSignals(False)

    def _on_cell_changed(self, row, column):
        if column == COL_GRADE:
            return  # 읽기전용 표시 칸 - 여기로 이벤트가 오면 무시

        asset_id_item = self.table.item(row, COL_IP)
        if not asset_id_item:
            return
        asset_id = asset_id_item.data(Qt.UserRole)

        def cell_text(col):
            item = self.table.item(row, col)
            return item.text().strip() if item else ""

        def cell_score(col):
            text = cell_text(col)
            if not text:
                return None
            try:
                v = int(text)
            except ValueError:
                return None
            return v if 1 <= v <= 3 else None

        purpose = cell_text(COL_PURPOSE)
        department = cell_text(COL_DEPT)
        owner = cell_text(COL_OWNER)
        c = cell_score(COL_C)
        i = cell_score(COL_I)
        a = cell_score(COL_A)

        # [입력값 검증] C/I/A 칸에 1~3 밖의 값을 넣으면 조용히 무시하지 않고
        # 원래 값으로 되돌려 사용자에게 알린다(잘못된 값이 등급 계산에 섞이는 것 방지).
        if column in (COL_C, COL_I, COL_A) and cell_text(column) and (
            (column == COL_C and c is None) or
            (column == COL_I and i is None) or
            (column == COL_A and a is None)
        ):
            QMessageBox.warning(self, "입력 오류", "C/I/A는 1~3 사이의 숫자만 입력할 수 있습니다.")
            self.load_data()
            return

        ok = self.db.update_asset_assessment(asset_id, purpose, department, owner, c, i, a)
        if not ok:
            QMessageBox.warning(self, "Error", "저장에 실패했습니다.")
            self.load_data()
            return

        self.table.blockSignals(True)
        grade_item = self.table.item(row, COL_GRADE)
        grade_item.setText(DBConnector.compute_asset_grade(c, i, a))
        self.table.blockSignals(False)
