# --------------------------------------------------------------------------
# Copyright © 2025 Z-VulnScan Team. All Rights Reserved.
#
# This software is proprietary and confidential.
# Unauthorized copying, modification, distribution, or reverse engineering
# of this file, via any medium, is strictly prohibited.
# --------------------------------------------------------------------------
"""
[수동/육안 점검 입력] 원격 접속(SSH/WinRM)이 안 되거나, 반출 제한 등으로 결과물을
파일로 못 옮기는 자산을 담당자가 화면으로 직접 보고 판정한 결과를 룰 코드별로
입력받는다. 저장은 자동 스캔과 동일하게 DBConnector.save_result()를 그대로
호출해 TBL_SCAN_RESULT에 쌓으므로, 이후 리포트(TXT/Excel/PDF) 생성은 기존
파이프라인을 그대로 탄다 - 담당자가 text_report.py의 [START]/[RESULT]/[REASON]
같은 원시 포맷을 직접 타이핑할 필요가 없다.

[실사용 중 발견된 데이터 유실 버그, 2026-08-04] 자산 콤보에서 아무 항목이나
클릭하면 _on_asset_picked()가 경고 없이 _load_ruleset()을 호출해 테이블 전체를
비웠다 - 실사용자가 항목 30개 가량을 입력한 상태에서 이 콤보를 건드려 전부
유실됨. 근본 수정: (1) 자산 선택은 IP/Hostname/유형만 채우고 테이블을 절대
자동으로 새로 안 부른다, (2) 그래도 남는 실수 경로(새로고침 버튼, 창 닫기, 크래시
등)에 안전망으로 매 입력마다 디스크에 초안(draft)을 자동 저장하고 다이얼로그를
다시 열면 복구를 제안한다 - 확인창 하나에만 의존하지 않는다.
"""
import json
import os
import sys
import uuid

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QComboBox, QLineEdit, QMessageBox, QHeaderView, QAbstractItemView
)

from utils import rule_crypto
from gui.dashboard_widgets import COLORS

# database_inspector.py의 f"{engine.upper()}-{code}" 규칙과 동일 - MySQL/PostgreSQL만
# vuln_code에 엔진 접두어가 붙고, kisa_code는 접두어 없는 원본 코드를 그대로 쓴다.
RULESETS = {
    "Linux": ("linux_rules.json", ""),
    "Windows": ("windows_rules.json", ""),
    "PC": ("pc_rules.json", ""),
    "Web/WAS": ("web_rules.json", ""),
    "MySQL": ("mysql_rules.json", "MYSQL-"),
    "PostgreSQL": ("postgresql_rules.json", "POSTGRESQL-"),
}

# [매크로 호환] 코드값(SAFE/VULNERABLE/...)은 text_report.py의 STATUS_TO_RESULT가
# "양호"/"취약"/"부분만족"/"N/A"(영문 그대로)로 재변환해 리포트에 박아넣는다 - 그쪽
# 매핑은 엑셀 수식이 그대로 비교하는 문자열이라 손대지 않는다. 여기 두 번째 값은
# "이 다이얼로그에서만 보이는" 한글 표시 라벨이라 자유롭게 바꿔도 리포트 출력엔
# 영향이 없다("N/A" -> "해당없음"으로 변경, 저장되는 코드값은 여전히 "NA").
STATUS_OPTIONS = [
    ("", "판정 안 함 (건너뜀)"),
    ("SAFE", "양호"),
    ("VULNERABLE", "취약"),
    ("PARTIAL", "부분만족"),
    ("NA", "해당없음"),
    ("MANUAL", "수동확인 필요"),
]


class NoScrollComboBox(QComboBox):
    """[UI 피드백: 마우스 스크롤에 따라 판정결과가 제멋대로 바뀜] 기본 QComboBox는
    호버 중에 마우스 휠 이벤트를 가로채 선택값을 바꾼다 - 테이블을 스크롤하려고
    휠을 굴렸는데 커서가 콤보 위에 있으면 그 항목의 판정이 바뀌어버림. 휠 이벤트를
    항상 무시(ignore)해서 위(테이블/스크롤영역)로 그대로 흘려보낸다 - 선택은
    클릭으로만 하게 된다."""
    def wheelEvent(self, event):
        event.ignore()


class ManualAuditDialog(QDialog):
    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("수동 진단 입력 (육안 점검)")
        self.resize(1150, 700)
        self.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['surface_2']};
                gridline-color: {COLORS['border']};
                selection-background-color: {COLORS['accent_bg']};
            }}
            QHeaderView::section {{
                background-color: {COLORS['surface_1']};
                color: {COLORS['text']};
                padding: 6px;
                border: 1px solid {COLORS['border']};
                font-weight: 600;
            }}
            /* 판정결과/현황/증적 - "입력칸"임이 한눈에 보이도록 흰 배경 + 또렷한 테두리 */
            QTableWidget QLineEdit, QTableWidget QComboBox {{
                background-color: white;
                color: {COLORS['text']};
                border: 1px solid {COLORS['accent']};
                border-radius: 3px;
                padding: 3px 6px;
            }}
            QTableWidget QLineEdit:focus, QTableWidget QComboBox:focus {{
                border: 2px solid {COLORS['accent']};
            }}
        """)
        self._rules = []
        self._prefix = ""
        # [Phase 2 이력 보존] 같은 세션에서 입력한 항목들을 하나로 묶어서 나중에
        # "이 자산, 이 시점에 수동으로 입력된 결과"임을 식별할 수 있게 함
        self._session_id = f"manual-{uuid.uuid4().hex[:8]}"

        layout = QVBoxLayout(self)

        info = QLabel(
            "원격 점검이 불가능한 자산을 직접 확인한 결과를 입력합니다. "
            "'판정 안 함'으로 둔 항목은 저장되지 않습니다. 입력 내용은 자동으로 임시 저장됩니다."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        # ---- 기존 자산 불러오기 ----
        asset_box = QHBoxLayout()
        asset_box.addWidget(QLabel("기존 자산에서 불러오기:"))
        self.asset_combo = NoScrollComboBox()
        self.asset_combo.addItem("-- 신규 입력 --", None)
        self._asset_rows = []
        for row in db.get_assets_for_manager():
            asset_id, ip, hostname = row[0], row[1], row[2]
            self._asset_rows.append(row)
            label = f"{ip} ({hostname})" if hostname and hostname != "-" else ip
            self.asset_combo.addItem(label, asset_id)
        self.asset_combo.currentIndexChanged.connect(self._on_asset_picked)
        asset_box.addWidget(self.asset_combo, 1)
        layout.addLayout(asset_box)

        form = QFormLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("예: 192.168.56.10")
        self.ip_input.editingFinished.connect(self._save_draft)
        self.hostname_input = QLineEdit()
        self.hostname_input.editingFinished.connect(self._save_draft)
        self.ruleset_combo = NoScrollComboBox()
        self.ruleset_combo.addItems(list(RULESETS.keys()))
        form.addRow("IP 주소 (필수):", self.ip_input)
        form.addRow("Hostname:", self.hostname_input)
        form.addRow("점검 대상 유형:", self.ruleset_combo)
        layout.addLayout(form)

        btn_load = QPushButton("항목 불러오기 / 새로고침")
        btn_load.clicked.connect(self._load_ruleset)
        layout.addWidget(btn_load)

        # ---- 항목별 입력 테이블 ----
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["코드", "항목명", "위험도", "판정결과", "현황(요약)", "증적(선택, 비우면 현황 재사용)"]
        )
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        # [UI 피드백: 내가 직접 넣는 칸만 반응하고 나머지는 아예 반응 없게]
        # 코드/항목명/위험도는 순수 표시용이라 선택/포커스/편집 자체가 안 일어나게
        # 막는다 - 실제 입력은 각 셀에 박아넣은 QComboBox/QLineEdit 위젯이 자기
        # 이벤트를 직접 처리하므로 테이블의 선택 모드와 무관하게 항상 정상 동작한다.
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setFocusPolicy(Qt.NoFocus)
        # [UI 피드백: 행이 너무 좁고 입력칸처럼 안 보임] 행 높이를 넉넉히 키우고,
        # 아래에서 현황/증적 칸을 QTableWidgetItem이 아니라 실제 QLineEdit 위젯으로
        # 박아넣어서(setCellWidget) 더블클릭 안 해도 항상 입력 상자로 보이게 한다.
        self.table.verticalHeader().setDefaultSectionSize(44)
        self.table.verticalHeader().setVisible(False)
        layout.addWidget(self.table, 1)

        # ---- 하단 버튼 ----
        btn_layout = QHBoxLayout()
        btn_save = QPushButton("저장 (판정 선택된 항목만)")
        btn_save.clicked.connect(self._save_all)
        btn_layout.addWidget(btn_save)
        btn_layout.addStretch()
        btn_close = QPushButton("닫기")
        btn_close.clicked.connect(self.close)
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)

        self._restore_draft_if_any()
        if self.table.rowCount() == 0:
            self._load_ruleset(skip_confirm=True)

    # ------------------------------------------------------------------
    # 미저장 확인 / 임시 저장(draft) - 실사용 중 발견된 데이터 유실 버그 대응
    # ------------------------------------------------------------------
    def _has_unsaved_input(self):
        """테이블에 판정결과가 선택됐거나 현황/증적에 뭐라도 입력돼 있으면 True."""
        for r in range(self.table.rowCount()):
            combo = self.table.cellWidget(r, 3)
            if combo and combo.currentData():
                return True
            for col in (4, 5):
                field = self.table.cellWidget(r, col)
                if field and field.text().strip():
                    return True
        return False

    def _draft_path(self):
        return os.path.join(os.path.dirname(self.db.db_path), "manual_audit_draft.json")

    def _save_draft(self):
        """판정/현황/증적 중 하나라도 바뀔 때마다 호출 - 디스크에 통째로 다시 쓴다.
        항목이 많아야 수십 개 수준의 짧은 문자열이라 매번 새로 써도 비용이 무시할
        만하다. 저장 실패는 조용히 무시한다(임시 저장은 best-effort, 메인 흐름을
        막으면 안 됨)."""
        rows = []
        for r in range(self.table.rowCount()):
            combo = self.table.cellWidget(r, 3)
            status = combo.currentData() if combo else ""
            detail_widget = self.table.cellWidget(r, 4)
            evidence_widget = self.table.cellWidget(r, 5)
            detail = detail_widget.text() if detail_widget else ""
            evidence = evidence_widget.text() if evidence_widget else ""
            if not status and not detail.strip() and not evidence.strip():
                continue
            code_item = self.table.item(r, 0)
            rows.append({
                "code": code_item.text() if code_item else "",
                "status": status,
                "detail": detail,
                "evidence": evidence,
            })

        if not rows and not self.ip_input.text().strip():
            self._clear_draft()
            return

        draft = {
            "ip": self.ip_input.text(),
            "hostname": self.hostname_input.text(),
            "ruleset_label": self.ruleset_combo.currentText(),
            "rows": rows,
        }
        try:
            with open(self._draft_path(), "w", encoding="utf-8") as f:
                json.dump(draft, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _clear_draft(self):
        try:
            os.remove(self._draft_path())
        except OSError:
            pass

    def _restore_draft_if_any(self):
        path = self._draft_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                draft = json.load(f)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            self._clear_draft()
            return

        rows = draft.get("rows", [])
        reply = QMessageBox.question(
            self, "이전 입력 복구",
            "이전에 저장하지 못하고 남은 입력이 있습니다.\n"
            f"IP: {draft.get('ip', '-')}  /  유형: {draft.get('ruleset_label', '-')}  /  항목 {len(rows)}개\n\n"
            "불러올까요? ('아니오'를 선택하면 이 임시 저장 내용은 삭제됩니다)",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
        )
        if reply != QMessageBox.Yes:
            self._clear_draft()
            return

        self.ip_input.setText(draft.get("ip", ""))
        self.hostname_input.setText(draft.get("hostname", ""))
        label = draft.get("ruleset_label", "")
        if label in RULESETS:
            self.ruleset_combo.setCurrentText(label)

        apply_rows = {row["code"]: row for row in rows if row.get("code")}
        self._load_ruleset(apply_rows=apply_rows, skip_confirm=True)

    def keyPressEvent(self, event):
        # [피드백: Esc 누르면 입력 중이던 내용이 바로 날아감] QDialog 기본 동작은
        # Esc = 즉시 reject()라 확인 절차가 없다. close()로 우회시켜서 closeEvent의
        # 미저장 확인 절차를 항상 거치게 한다.
        if event.key() == Qt.Key_Escape:
            event.accept()
            self.close()
            return
        super().keyPressEvent(event)

    def closeEvent(self, event):
        if self._has_unsaved_input():
            reply = QMessageBox.question(
                self, "닫기 확인",
                "저장하지 않은 입력 내용이 있습니다. 정말 닫으시겠습니까?\n"
                "(DB에는 반영되지 않지만, 임시 저장은 남아있어 다음에 다시 열면 복구할 수 있습니다)",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                event.ignore()
                return
        event.accept()

    def _on_asset_picked(self):
        """[버그 수정] 예전엔 여기서 _load_ruleset()을 자동 호출해서 입력 중이던
        테이블을 경고 없이 통째로 비워버렸다(실사용 중 30개 가량 입력분 유실 확인됨).
        이제는 IP/Hostname/유형만 채우고, 실제 룰 목록을 새로 불러올지는 사용자가
        "항목 불러오기" 버튼으로 명시적으로 결정한다(그때는 미저장 확인을 거침)."""
        asset_id = self.asset_combo.currentData()
        if asset_id is None:
            return
        for row in self._asset_rows:
            if row[0] == asset_id:
                _, ip, hostname, os_type = row[0], row[1], row[2], row[3]
                self.ip_input.setText(ip)
                self.hostname_input.setText(hostname or "")
                os_lower = (os_type or "").lower()
                for label in RULESETS:
                    if label.lower() in os_lower:
                        self.ruleset_combo.setCurrentText(label)
                        break
                break

    @staticmethod
    def _rules_base_path():
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            current_file = os.path.abspath(__file__)
            base_path = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        rules_dir = os.path.join(base_path, 'rules')
        if hasattr(sys, '_MEIPASS') and not os.path.isdir(rules_dir):
            rules_dir = os.path.join(sys._MEIPASS, 'rules')
        return rules_dir

    def _load_ruleset(self, apply_rows=None, skip_confirm=False):
        if not skip_confirm and self._has_unsaved_input():
            reply = QMessageBox.question(
                self, "새로고침 확인",
                "현재 입력 중인 내용이 있습니다. 새로 불러오면 저장하지 않은 내용은 사라집니다.\n"
                "계속할까요?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return

        label = self.ruleset_combo.currentText()
        filename, prefix = RULESETS[label]
        path = os.path.join(self._rules_base_path(), filename)
        try:
            self._rules = rule_crypto.load_ruleset(path)
        except Exception as e:
            QMessageBox.critical(self, "룰셋 로드 실패", f"{filename} 을(를) 불러오지 못했습니다:\n{e}")
            self._rules = []
        self._prefix = prefix

        self.table.setRowCount(len(self._rules))
        for r, rule in enumerate(self._rules):
            # 읽기 전용 3칸(코드/항목명/위험도) - 회색 텍스트 + 옅은 배경으로
            # 아래 입력칸(흰 배경 + 파란 테두리)과 시각적으로 확실히 구분되게 한다.
            for col, value in ((0, rule.get('code', '')), (1, rule.get('name', '')), (2, rule.get('importance', '중'))):
                item = QTableWidgetItem(value)
                # 편집/선택 둘 다 꺼서 클릭해도 하이라이트조차 안 되는 순수 표시 전용으로 만든다
                item.setFlags(item.flags() & ~Qt.ItemIsEditable & ~Qt.ItemIsSelectable)
                item.setForeground(QColor(COLORS['text_secondary']))
                item.setBackground(QColor(COLORS['surface_1']))
                self.table.setItem(r, col, item)

            saved_row = apply_rows.get(rule.get('code', '')) if apply_rows else None

            combo = NoScrollComboBox()
            for value, kr_label in STATUS_OPTIONS:
                combo.addItem(kr_label, value)
            if saved_row and saved_row.get("status"):
                idx = combo.findData(saved_row["status"])
                if idx >= 0:
                    combo.setCurrentIndex(idx)
            combo.currentIndexChanged.connect(self._save_draft)
            self.table.setCellWidget(r, 3, combo)

            detail_edit = QLineEdit(saved_row.get("detail", "") if saved_row else "")
            detail_edit.setPlaceholderText("예: pam_securetty 설정 확인함")
            detail_edit.editingFinished.connect(self._save_draft)
            self.table.setCellWidget(r, 4, detail_edit)

            evidence_edit = QLineEdit(saved_row.get("evidence", "") if saved_row else "")
            evidence_edit.setPlaceholderText("비우면 왼쪽 현황을 그대로 사용")
            evidence_edit.editingFinished.connect(self._save_draft)
            self.table.setCellWidget(r, 5, evidence_edit)

    def _save_all(self):
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "입력 필요", "IP 주소는 필수입니다.")
            return

        hostname = self.hostname_input.text().strip() or "Unknown"
        os_label = self.ruleset_combo.currentText()
        asset_id = self.db.save_asset(ip, hostname=hostname, os_type=os_label, hostname_source="수동입력")
        if not asset_id:
            QMessageBox.critical(self, "저장 실패", "자산 정보를 저장하지 못했습니다.")
            return

        saved = 0
        for r, rule in enumerate(self._rules):
            combo = self.table.cellWidget(r, 3)
            status = combo.currentData()
            if not status:
                continue  # "판정 안 함" - 건너뜀

            detail_text = self.table.cellWidget(r, 4).text().strip()
            evidence_text = self.table.cellWidget(r, 5).text().strip()
            if not evidence_text:
                evidence_text = detail_text

            code = rule.get('code', '')
            vuln_code = f"{self._prefix}{code}"
            ok = self.db.save_result(
                asset_id, vuln_code, rule.get('name', code),
                rule.get('importance', '중'), status, detail_text or "-",
                remediation=rule.get('remediation', '-'),
                raw_output=evidence_text,
                kisa_code=code,
                session_id=self._session_id,
                operator="수동입력",
            )
            if ok:
                saved += 1

        if saved:
            self._clear_draft()
            QMessageBox.information(
                self, "저장 완료",
                f"{saved}개 항목이 저장되었습니다.\n"
                "같은 자산에 이어서 다른 유형(예: PC 다음 Web)도 입력할 수 있습니다."
            )
        else:
            QMessageBox.information(self, "저장 없음", "판정결과가 선택된 항목이 없습니다.")
