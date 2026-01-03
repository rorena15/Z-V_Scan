# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
import sys
from PySide6.QtWidgets import (
                                QDialog, QVBoxLayout, QHBoxLayout, QPushButton, 
                                QTableWidget, QTableWidgetItem, QHeaderView, 
                                QMessageBox, QLabel, QAbstractItemView
                                )
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

class DatabaseManagerDialog(QDialog):
    def __init__(self, db_connector, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Database Manager - Asset Control")
        self.resize(900, 600)
        self.db = db_connector
        
        # 다크 테마 적용
        self.setStyleSheet("""
            QDialog { background-color: #2b2b2b; color: white; }
            QTableWidget { 
                background-color: #333; 
                color: #ddd; 
                gridline-color: #555; 
                selection-background-color: #2e7d32; 
            }
            QHeaderView::section { background-color: #444; color: white; padding: 5px; border: 1px solid #555; }
            QPushButton {
                background-color: #444; color: white; border: 1px solid #666;
                padding: 6px 12px; border-radius: 4px; font-weight: bold;
            }
            QPushButton:hover { background-color: #666; }
            QPushButton:pressed { background-color: #222; }
            QLabel { color: #aaa; }
        """)

        self.layout = QVBoxLayout(self)
        self.initUI()
        self.load_data()

    def initUI(self):
        # 1. 상단 안내 및 버튼
        top_layout = QHBoxLayout()
        
        info_lbl = QLabel("💡 팁: 셀을 더블 클릭하면 내용을 수정할 수 있습니다. (IP는 수정 불가)")
        
        btn_refresh = QPushButton("🔄 새로고침 (Refresh)")
        btn_refresh.clicked.connect(self.load_data)
        
        btn_delete = QPushButton("🗑️ 선택 삭제 (Delete)")
        btn_delete.setStyleSheet("background-color: #c62828; border-color: #8e0000;") # 빨간색
        btn_delete.clicked.connect(self.delete_selected_row)

        top_layout.addWidget(info_lbl)
        top_layout.addStretch()
        top_layout.addWidget(btn_refresh)
        top_layout.addWidget(btn_delete)
        
        self.layout.addLayout(top_layout)

        # 2. 데이터 테이블
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["ID", "IP Address", "Hostname", "OS Type", "MAC Addr", "Last Seen", "Memo"])
        
        # 헤더 설정
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents) # ID는 좁게
        
        # 선택 모드 (행 단위 선택)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        
        # 수정 감지 이벤트 연결
        self.table.cellChanged.connect(self.on_cell_changed)
        
        self.layout.addWidget(self.table)
        
        # 3. 하단 닫기 버튼
        close_layout = QHBoxLayout()
        close_layout.addStretch()
        btn_close = QPushButton("닫기 (Close)")
        btn_close.clicked.connect(self.accept)
        close_layout.addWidget(btn_close)
        self.layout.addLayout(close_layout)

    def load_data(self):
        """DB에서 데이터를 가져와 테이블에 뿌리기"""
        self.table.blockSignals(True) # 로딩 중 이벤트 발생 방지
        self.table.setRowCount(0)
        
        assets = self.db.get_assets_for_manager()
        
        for row_idx, row_data in enumerate(assets):
            self.table.insertRow(row_idx)
            # row_data: (id, ip, host, os, mac, last, memo)
            
            for col_idx, value in enumerate(row_data):
                item = QTableWidgetItem(str(value) if value is not None else "")
                
                # ID와 IP, LastSeen은 수정 불가능하게 설정 (Read Only)
                if col_idx in [0, 1, 5]: 
                    item.setFlags(item.flags() ^ Qt.ItemIsEditable)
                    item.setForeground(QColor("#888888")) # 회색 처리
                else:
                    item.setForeground(QColor("#ffffff"))
                
                # ID 컬럼에 실제 Asset ID 저장 (숨겨진 데이터)
                if col_idx == 0:
                    item.setData(Qt.UserRole, value) 

                self.table.setItem(row_idx, col_idx, item)
                
        self.table.blockSignals(False)

    def on_cell_changed(self, row, column):
        """셀 내용이 변경되면 DB에 즉시 반영"""
        item = self.table.item(row, column)
        new_value = item.text()
        
        # Asset ID 가져오기 (0번 컬럼에 저장됨)
        asset_id_item = self.table.item(row, 0)
        asset_id = int(asset_id_item.text())
        
        # 컬럼 인덱스를 DB 필드명으로 매핑
        col_map = {
            2: "hostname",
            3: "os_type",
            4: "mac_addr",
            6: "memo"
        }
        
        if column in col_map:
            field_name = col_map[column]
            success = self.db.update_asset_field(asset_id, field_name, new_value)
            
            if not success:
                QMessageBox.warning(self, "Error", "수정에 실패했습니다.")
                self.load_data() # 원복

    def delete_selected_row(self):
        """선택된 행 삭제"""
        current_row = self.table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "삭제할 자산을 선택해주세요.")
            return
            
        ip = self.table.item(current_row, 1).text()
        asset_id = int(self.table.item(current_row, 0).text())
        
        reply = QMessageBox.question(
            self, "삭제 확인", 
            f"정말로 삭제하시겠습니까?\nTarget: {ip}\n\n(관련된 모든 스캔 기록이 함께 삭제됩니다.)",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            if self.db.delete_asset_by_id(asset_id):
                self.table.removeRow(current_row)
                QMessageBox.information(self, "Success", "삭제되었습니다.")
            else:
                QMessageBox.critical(self, "Error", "DB 삭제 중 오류가 발생했습니다.")