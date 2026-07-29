# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[Phase 2/3] Waiver(예외처리) 관리: 특정 자산의 특정 진단 항목을 예외처리하거나 해제한다.
예외처리 시 사유와 승인자 입력을 필수로 요구해 감사 추적성을 보장한다.
"""
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QComboBox, QMessageBox, QLineEdit,
    QHeaderView, QAbstractItemView
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor


class WaiverInputDialog(QDialog):
    """예외처리 시 사유+승인자를 강제로 입력받는 폼 (둘 다 필수)"""
    def __init__(self, code_label, parent=None):
        super().__init__(parent)
        self.setWindowTitle("예외처리 승인 정보")
        self.resize(420, 180)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"대상 항목: {code_label}"))

        layout.addWidget(QLabel("예외처리 사유 (필수):"))
        self.reason_input = QLineEdit()
        layout.addWidget(self.reason_input)

        layout.addWidget(QLabel("승인자 (필수):"))
        self.approver_input = QLineEdit()
        layout.addWidget(self.approver_input)

        btn_layout = QHBoxLayout()
        btn_ok = QPushButton("확인")
        btn_ok.clicked.connect(self._on_ok)
        btn_cancel = QPushButton("취소")
        btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)

    def _on_ok(self):
        if not self.reason_input.text().strip() or not self.approver_input.text().strip():
            QMessageBox.warning(self, "입력 필요", "사유와 승인자는 반드시 입력해야 합니다.")
            return
        self.accept()

    def values(self):
        return self.reason_input.text().strip(), self.approver_input.text().strip()


class WaiverManagerDialog(QDialog):
    STATUS_LABEL = {"VULNERABLE": "취약", "SAFE": "양호", "PARTIAL": "부분만족", "NA": "해당없음", "MANUAL": "검토필요", "ERROR": "점검불가"}
    # [Phase 3: UI 재구성] 상태 배지 범례 - Excel/PDF 리포트의 색상 체계와 맞춤
    STATUS_COLORS = {
        "VULNERABLE": "#e74c3c", "SAFE": "#2ecc71", "PARTIAL": "#f1c40f",
        "NA": "#7f8c8d", "MANUAL": "#e67e22", "ERROR": "#95a5a6",
    }

    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("예외처리(Waiver) 관리")
        self.resize(1000, 600)

        self._asset_rows = []  # (asset_id, ip, hostname)

        layout = QVBoxLayout(self)

        top = QHBoxLayout()
        top.addWidget(QLabel("자산:"))
        self.asset_combo = QComboBox()
        self.asset_combo.currentIndexChanged.connect(self._load_results)
        top.addWidget(self.asset_combo, 1)
        btn_refresh = QPushButton("새로고침")
        btn_refresh.clicked.connect(self._reload_assets)
        top.addWidget(btn_refresh)
        layout.addLayout(top)

        # [Phase 3: UI 재구성] 상태 배지 범례 - 아래 표의 "상태" 컬럼 색상이 무엇을 뜻하는지 안내
        legend = QHBoxLayout()
        legend.addWidget(QLabel("범례:"))
        for status, label in self.STATUS_LABEL.items():
            badge = QLabel(f" {label} ")
            color = self.STATUS_COLORS.get(status, "#666")
            badge.setStyleSheet(
                f"background-color: {color}; color: white; border-radius: 4px; padding: 2px 8px; font-weight: bold; font-size: 8pt;"
            )
            legend.addWidget(badge)
        legend.addStretch()
        layout.addLayout(legend)

        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["코드", "항목명", "위험도", "상태", "예외처리", "사유", "승인자/일자"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        btn_waive = QPushButton("선택 항목 예외처리")
        btn_waive.clicked.connect(self._waive_selected)
        btn_unwaive = QPushButton("선택 항목 예외 해제")
        btn_unwaive.clicked.connect(self._unwaive_selected)
        btn_layout.addWidget(btn_waive)
        btn_layout.addWidget(btn_unwaive)
        btn_layout.addStretch()
        btn_close = QPushButton("닫기")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)

        self._reload_assets()

    def _reload_assets(self):
        self.asset_combo.blockSignals(True)
        self.asset_combo.clear()
        self._asset_rows = []
        for row in self.db.get_assets_for_manager():
            asset_id, ip, hostname, os_type = row[0], row[1], row[2], row[3]
            self._asset_rows.append((asset_id, ip, hostname))
            label = f"{ip} ({hostname})" if hostname and hostname != "-" else ip
            self.asset_combo.addItem(label)
        self.asset_combo.blockSignals(False)
        self._load_results()

    def _current_asset_id(self):
        idx = self.asset_combo.currentIndex()
        if idx < 0 or idx >= len(self._asset_rows):
            return None
        return self._asset_rows[idx][0]

    def _load_results(self):
        self.table.setRowCount(0)
        asset_id = self._current_asset_id()
        if asset_id is None:
            return

        results = self.db.get_latest_results_for_asset(asset_id)
        self.table.setRowCount(len(results))
        for r, row in enumerate(results):
            result_id, code, kisa_code, name, risk, status, waived, reason, approver, wdate = row
            display_code = kisa_code or code

            self.table.setItem(r, 0, QTableWidgetItem(display_code))
            self.table.setItem(r, 1, QTableWidgetItem(name or ""))
            self.table.setItem(r, 2, QTableWidgetItem(risk or ""))

            status_item = QTableWidgetItem(self.STATUS_LABEL.get(status, status or ""))
            # [Phase 3: UI 재구성] 위 범례와 동일한 색상으로 상태 배지 표시
            color = self.STATUS_COLORS.get(status)
            if color:
                status_item.setBackground(QColor(color))
                status_item.setForeground(QColor("white"))
            self.table.setItem(r, 3, status_item)

            waived_item = QTableWidgetItem("예외처리됨" if waived == 1 else "-")
            self.table.setItem(r, 4, waived_item)
            self.table.setItem(r, 5, QTableWidgetItem(reason or ""))
            approver_info = f"{approver} ({wdate})" if approver else ""
            self.table.setItem(r, 6, QTableWidgetItem(approver_info))

            # result_id를 행 데이터로 보관 (0번 컬럼 아이템에)
            self.table.item(r, 0).setData(Qt.UserRole, result_id)

    def _waive_selected(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Notice", "예외처리할 항목을 선택하세요.")
            return
        result_id = self.table.item(row, 0).data(Qt.UserRole)
        code_label = f"{self.table.item(row, 0).text()} - {self.table.item(row, 1).text()}"

        dlg = WaiverInputDialog(code_label, self)
        if dlg.exec() != QDialog.Accepted:
            return
        reason, approver = dlg.values()

        if self.db.set_waiver(result_id, True, reason=reason, approver=approver):
            self._load_results()
        else:
            QMessageBox.critical(self, "Error", "예외처리 저장에 실패했습니다.")

    def _unwaive_selected(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Notice", "예외 해제할 항목을 선택하세요.")
            return
        result_id = self.table.item(row, 0).data(Qt.UserRole)

        reply = QMessageBox.question(
            self, "예외 해제 확인", "선택한 항목의 예외처리를 해제하시겠습니까?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        if self.db.set_waiver(result_id, False):
            self._load_results()
        else:
            QMessageBox.critical(self, "Error", "예외 해제에 실패했습니다.")
