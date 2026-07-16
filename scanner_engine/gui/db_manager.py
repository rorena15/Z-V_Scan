# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
# 
# This software is proprietary and confidential. 
# Unauthorized copying, modification, distribution, or reverse engineering 
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
from PySide6.QtWidgets import (
                                QDialog, QVBoxLayout, QHBoxLayout, QPushButton,
                                QTableWidget, QTableWidgetItem, QHeaderView,
                                QMessageBox, QLabel, QAbstractItemView, QComboBox
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
        
        info_lbl = QLabel("팁: 셀을 더블 클릭하면 내용을 수정할 수 있습니다. (IP/Port는 수정 불가)")

        # [자산 태그/그룹 관리] 구역별(DMZ, 제어망 A 등) 필터 - load_data()가 채워준다
        self.zone_filter_combo = QComboBox()
        self.zone_filter_combo.addItem("전체 구역")
        self.zone_filter_combo.currentIndexChanged.connect(self._apply_zone_filter)

        btn_refresh = QPushButton("새로고침 (Refresh)")
        btn_refresh.clicked.connect(self.load_data)

        btn_delete = QPushButton("선택 삭제 (Delete)")
        btn_delete.setStyleSheet("background-color: #c62828; border-color: #8e0000;") # 빨간색
        btn_delete.clicked.connect(self.delete_selected_row)

        top_layout.addWidget(info_lbl)
        top_layout.addStretch()
        top_layout.addWidget(QLabel("구역 필터:"))
        top_layout.addWidget(self.zone_filter_combo)
        top_layout.addWidget(btn_refresh)
        top_layout.addWidget(btn_delete)

        self.layout.addLayout(top_layout)

        # 2. 데이터 테이블
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels(["ID", "IP Address", "Hostname", "OS Type", "MAC Addr", "Port", "Last Seen", "Memo", "Zone Tag"])

        # 헤더 설정
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents) # ID는 좁게
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents) # port는 길수도 있으니
        
        # 선택 모드 (행 단위 선택)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        
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

    def get_all_assets(self):
        #프로그램 시작 시 로드할 모든 자산 목록 가져오기
        conn = self._connect()
        cursor = conn.cursor()
        try:
            # UI 테이블 순서에 맞춰서 데이터 조회 (IP, Host, OS, MAC, Vendor)
            query = "SELECT ip_addr, hostname, os_type, mac_addr, vendor FROM TBL_ASSETS ORDER BY asset_id ASC"
            cursor.execute(query)
            return cursor.fetchall() # 리스트 반환: [(ip, host, os, mac, vendor), ...]
        except Exception as e:
            # 테이블이 없거나 에러나면 빈 리스트 반환 (프로그램 켜질 때 죽지 않게)
            return []
        finally:
            conn.close()

    def load_data(self):
        """DB에서 데이터를 가져와 테이블에 뿌리기"""
        self.table.blockSignals(True) # 로딩 중 이벤트 발생 방지
        self.table.setRowCount(0)

        self._all_assets = self.db.get_assets_for_manager()

        # [자산 태그/그룹 관리] 현재 존재하는 구역 태그들로 필터 콤보를 채운다
        # (currentIndexChanged가 재호출되지 않도록 콤보에도 blockSignals)
        self.zone_filter_combo.blockSignals(True)
        current_filter = self.zone_filter_combo.currentText()
        self.zone_filter_combo.clear()
        self.zone_filter_combo.addItem("전체 구역")
        zone_tags = sorted({row[8] for row in self._all_assets if row[8]})
        for tag in zone_tags:
            self.zone_filter_combo.addItem(tag)
        idx = self.zone_filter_combo.findText(current_filter)
        self.zone_filter_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.zone_filter_combo.blockSignals(False)

        self._populate_table(self._all_assets)
        self.table.blockSignals(False)

    def _apply_zone_filter(self):
        selected = self.zone_filter_combo.currentText()
        self.table.blockSignals(True)
        if selected == "전체 구역":
            self._populate_table(self._all_assets)
        else:
            self._populate_table([row for row in self._all_assets if row[8] == selected])
        self.table.blockSignals(False)

    def _populate_table(self, assets):
        self.table.setRowCount(0)
        for row_idx, row_data in enumerate(assets):
            self.table.insertRow(row_idx)
            # row_data: (id, ip, host, os, mac, ports, last, memo, zone_tag)

            for col_idx, value in enumerate(row_data):
                val_str = str(value) if value is not None else ""
                item = QTableWidgetItem(val_str)

                # 수정 불가 컬럼: ID(0), IP(1), Port(5), LastSeen(6)
                if col_idx in [0, 1, 5, 6]:
                    # 플래그를 조작해서 '수정 가능(ItemIsEditable)' 속성을 끕니다.
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    item.setForeground(QColor("#888888")) # 회색 (비활성 느낌)
                else:
                    item.setForeground(QColor("#ffffff"))

                # ID 저장 (나중에 수정/삭제할 때 씀)
                if col_idx == 0:
                    item.setData(Qt.UserRole, value)

                self.table.setItem(row_idx, col_idx, item)

    def on_cell_changed(self, row, column):
        """셀 내용이 변경되면 DB에 즉시 반영"""
        item = self.table.item(row, column)
        if not item: return
        new_value = item.text()

        # 0번 컬럼에 숨겨둔 asset_id 가져오기
        asset_id_item = self.table.item(row, 0)
        asset_id = int(asset_id_item.data(Qt.UserRole))

        # [버그 수정] 기존 코드는 실제 데이터 순서(mac_addr가 4번, open_ports가 5번)와
        # 반대로 가정하고 있어서, MAC Addr 칸은 수정이 막혀 있고 대신 수정 가능한
        # Port 칸을 고치면 그 값이 조용히 mac_addr DB 컬럼에 저장되고 있었다.
        col_map = {
            2: "hostname",  # Hostname
            3: "os_type",   # OS
            4: "mac_addr",  # MAC Addr
            # 5: Port (수정 불가이므로 매핑 없음)
            7: "memo",      # Memo
            8: "zone_tag",  # Zone Tag
        }

        if column in col_map:
            field_name = col_map[column]
            success = self.db.update_asset_field(asset_id, field_name, new_value)
            
            if not success:
                QMessageBox.warning(self, "Error", "수정에 실패했습니다.")
                # 실패하면 다시 로드해서 원복
                self.load_data()

    def delete_selected_row(self):
        """선택된 여러 행을 한꺼번에 삭제"""
        selection = self.table.selectedIndexes()
        if not selection:
            QMessageBox.warning(self, "Warning", "삭제할 자산을 선택해주세요.")
            return
        # 중복된 행 번호를 제거하고, 뒤에서부터 지우기 위해 내림차순 정렬 (중요!)
        # (앞에서부터 지우면 인덱스가 밀려서 엉뚱한 게 지워짐)
        selected_rows = sorted(list(set(index.row() for index in selection)), reverse=True)
        count = len(selected_rows)
        reply = QMessageBox.question(
            self, "삭제 확인", 
            f"선택한 {count}개 항목을 정말로 삭제하시겠습니까?\n\n(관련된 모든 스캔 기록이 함께 영구 삭제됩니다.)",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        success_count = 0
        # 선택된 행들을 하나씩 순회하며 삭제
        for row in selected_rows:
            try:
                # 0번 컬럼(ID) 값 가져오기
                asset_id_item = self.table.item(row, 0)
                if not asset_id_item: continue
                    
                asset_id = int(asset_id_item.text())
                
                # DB에서 삭제 성공 시 UI 테이블에서도 제거
                if self.db.delete_asset_by_id(asset_id): #
                    self.table.removeRow(row)
                    success_count += 1
            except Exception as e:
                print(f"[Delete Error] Row {row}: {e}")

        if success_count > 0:
            QMessageBox.information(self, "Success", f"{success_count}개 항목이 삭제되었습니다.")
        else:
            QMessageBox.warning(self, "Fail", "삭제에 실패했습니다.")