# gui_qt.py
# deps: PySide6 qasync stem
import sys, asyncio, os, shutil, socket
from typing import Dict, Optional

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QTextEdit, QPushButton, QListWidget, QListWidgetItem,
    QCheckBox, QSplitter
)
from PySide6.QtCore import QObject, Signal, Qt
from qasync import QEventLoop, asyncSlot

from bootstrap import ensure_initialized
from node import Node
from store import Store

# ───────────────────────── Tor manager + helpers ─────────────────────────

try:
    from stem.process import launch_tor_with_config
except Exception:
    launch_tor_with_config = None  # we’ll show a clear error if user enables Tor

def _probe_local_socks(port: int) -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
        s.close()
        return True
    except Exception:
        return False

def _find_tor_binary() -> str | None:
    # env override first
    tor_path = os.environ.get("TOR_BINARY")
    if tor_path and os.path.exists(tor_path):
        return tor_path
    # PATH
    tor_path = shutil.which("tor")
    if tor_path:
        return tor_path
    # common mac/linux paths
    for p in ("/opt/homebrew/bin/tor", "/usr/local/bin/tor", "/usr/bin/tor"):
        if os.path.exists(p):
            return p
    # common Windows paths
    for p in (
        r"C:\Program Files\Tor\tor.exe",
        r"C:\Program Files (x86)\Tor\tor.exe",
    ):
        if os.path.exists(p):
            return p
    return None

def _find_free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]; s.close(); return port

class TorManager:
    """Reuses system Tor on 127.0.0.1:9050 if present, else launches a private Tor."""
    def __init__(self):
        self.proc = None
        self.socks_port = None
        self.data_dir = None
        self.enabling = False  # debounce flag

    async def start(self, profile_dir: str) -> str:
        # reuse system Tor if already running
        if _probe_local_socks(9050):
            self.proc = None
            self.socks_port = 9050
            return "socks5h://127.0.0.1:9050"

        # already launched privately?
        if self.proc and self.socks_port:
            return f"socks5h://127.0.0.1:{self.socks_port}"

        if launch_tor_with_config is None:
            raise RuntimeError("Missing dependency: pip install stem")

        tor_bin = _find_tor_binary()
        if not tor_bin:
            raise RuntimeError("'tor' isn't available on your system or PATH. Install it (e.g., brew install tor).")

        self.enabling = True
        self.socks_port = _find_free_port()
        self.data_dir = os.path.join(profile_dir, "tor")
        os.makedirs(self.data_dir, exist_ok=True)

        def _launch():
            return launch_tor_with_config(
                tor_cmd=tor_bin,
                config={
                    "SocksPort": str(self.socks_port),
                    "DataDirectory": self.data_dir,
                    "AvoidDiskWrites": "1",
                    "ClientOnly": "1",
                },
                take_ownership=True,
                timeout=90,
            )
        self.proc = await asyncio.to_thread(_launch)
        self.enabling = False
        return f"socks5h://127.0.0.1:{self.socks_port}"

    async def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
            except Exception:
                pass
        self.proc = None
        self.socks_port = None

# ───────────────────────── bridge ─────────────────────────

class Bridge(QObject):
    delivered = Signal(str, str, str)  # sender_pub, text, msg_id

# ───────────────────────── chat pane ─────────────────────────

class ChatPane(QWidget):
    def __init__(self, peer_pub: str, peer_name: str, node: Node):
        super().__init__()
        self.peer_pub = peer_pub
        self.peer_name = peer_name or (peer_pub[:8] + "…")
        self.node = node

        self.title = QLabel(self.peer_name)
        self.title.setStyleSheet("font-weight: bold;")
        self.view = QTextEdit(); self.view.setReadOnly(True)
        self.input = QLineEdit(); self.input.setPlaceholderText("Type a message and press Enter")
        self.send_btn = QPushButton("Send")

        col = QVBoxLayout()
        col.addWidget(self.title)
        col.addWidget(self.view)
        row = QHBoxLayout()
        row.addWidget(self.input); row.addWidget(self.send_btn)
        col.addLayout(row)
        self.setLayout(col)

        self.send_btn.clicked.connect(self._send)
        self.input.returnPressed.connect(self._send)

    def rename(self, name: str):
        if name:
            self.peer_name = name
            self.title.setText(name)

    def append_incoming(self, text: str):
        self.view.append(f"<b>{self.peer_name}:</b> {text}")

    def append_outgoing(self, text: str):
        self.view.append(f"<b>You:</b> {text}")

    def _send(self):
        txt = self.input.text().strip()
        if not txt:
            return
        try:
            self.node.send_text(self.peer_pub, txt)
            self.append_outgoing(txt)
            self.input.clear()
        except Exception as e:
            self.view.append(f"<i>Send error: {e}</i>")

# ───────────────────────── main window ─────────────────────────

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MeshMsg (alpha)")

        self.bridge = Bridge()
        self.bridge.delivered.connect(self.on_delivered)

        # Top: username, register/start, address
        self.user_edit = QLineEdit(); self.user_edit.setPlaceholderText("Choose a username")
        self.addr_value = QLineEdit(); self.addr_value.setReadOnly(True)
        self.register_btn = QPushButton("Register / Start")

        top = QHBoxLayout()
        top.addWidget(QLabel("Username:")); top.addWidget(self.user_edit)
        top.addWidget(self.register_btn)
        top.addWidget(QLabel("Address:")); top.addWidget(self.addr_value)

        # Left column: People (live peers) + controls
        self.people = QListWidget()
        self.start_chat_btn = QPushButton("Start Chat")

        left = QVBoxLayout()
        left.addWidget(QLabel("People (nearby):"))
        left.addWidget(self.people)
        left.addWidget(self.start_chat_btn)

        # Right column: Chats list + current chat pane
        self.chats = QListWidget()
        self.chat_container = QWidget()
        self.chat_slot = QVBoxLayout(); self.chat_slot.setContentsMargins(0,0,0,0)
        self.chat_container.setLayout(self.chat_slot)

        right = QVBoxLayout()
        right.addWidget(QLabel("Chats:"))
        right.addWidget(self.chats)
        right.addWidget(self.chat_container)

        # Safety/Admin
        self.tor_check = QCheckBox("Safety (Tor)")
        self.admin_check = QCheckBox("Admin (bypass ACL)")
        ctrl = QHBoxLayout()
        ctrl.addWidget(self.tor_check)
        ctrl.addWidget(self.admin_check)

        # Status log
        self.log = QTextEdit(); self.log.setReadOnly(True)

        # Split layout
        split = QSplitter()
        left_wrap = QWidget(); left_wrap.setLayout(left)
        right_wrap = QWidget(); right_wrap.setLayout(right)
        split.addWidget(left_wrap); split.addWidget(right_wrap)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 2)

        # Main layout
        root = QVBoxLayout()
        root.addLayout(top)
        root.addWidget(split)
        root.addLayout(ctrl)
        root.addWidget(QLabel("Status:"))
        root.addWidget(self.log)
        self.setLayout(root)

        # Wire events
        self.register_btn.clicked.connect(self._on_register_clicked)
        self.start_chat_btn.clicked.connect(self._on_start_chat_clicked)
        self.people.itemDoubleClicked.connect(self._on_people_double_clicked)
        self.chats.currentRowChanged.connect(self._on_select_chat)
        self.tor_check.toggled.connect(self._on_tor_toggled)
        self.tor_active = False
        self.admin_check.stateChanged.connect(self._on_admin_toggle)

        # Runtime
        self.node: Optional[Node] = None
        self.store: Optional[Store] = None
        self.cfg_path: Optional[str] = None
        self.tor = TorManager()
        self._pane_by_pub: Dict[str, ChatPane] = {}
        self._chat_item_by_pub: Dict[str, QListWidgetItem] = {}

    async def start_node(self):
        self.log.append("Enter a username and click 'Register / Start'.\n")

    async def stop_node(self):
        if self.node:
            await self.node.stop()
            self.node = None
        self.store = None
        self.addr_value.clear()
        self.people.clear()
        self.chats.clear()
        self._pane_by_pub.clear()
        self._chat_item_by_pub.clear()
        self._clear_chat_pane()
        self.log.append("Node stopped.\n")

    # ── helpers ──
    def _clear_chat_pane(self):
        while self.chat_slot.count():
            item = self.chat_slot.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)

    def _ensure_chat(self, pub: str, uname: Optional[str] = None) -> ChatPane:
        pane = self._pane_by_pub.get(pub)
        if pane:
            if uname:
                pane.rename(uname)
            return pane
        pane = ChatPane(pub, uname or (pub[:8] + "…"), self.node)
        self._pane_by_pub[pub] = pane
        li = self._chat_item_by_pub.get(pub)
        if not li:
            label = uname or (pub[:8] + "…")
            li = QListWidgetItem(label)
            li.setData(Qt.UserRole, pub)
            self.chats.addItem(li)
            self._chat_item_by_pub[pub] = li
        if self.chats.count() == 1:
            self._show_chat(pub)
        return pane

    def _show_chat(self, pub: str):
        pane = self._pane_by_pub.get(pub)
        if not pane:
            return
        self._clear_chat_pane()
        self.chat_slot.addWidget(pane)
        it = self._chat_item_by_pub.get(pub)
        if it:
            row = self.chats.row(it)
            if row >= 0:
                self.chats.setCurrentRow(row)
                it.setText((self.store.username_for(pub) or pub[:8] + "…"))

    def _refresh_people(self):
        if not self.store:
            return
        self.people.clear()
        # show only recently-seen peers so “ghosts” don’t appear
        for p in self.store.recent_peers(max_age=30):
            uname = p.get("username") or (p["pubkey"][:8] + "…")
            it = QListWidgetItem(uname)
            it.setData(Qt.UserRole, p["pubkey"])
            self.people.addItem(it)

    async def _auto_refresh(self):
        while self.node:
            self._refresh_people()
            await asyncio.sleep(3)

    # ── signals ──
    def on_delivered(self, sender_pub: str, text: str, mid: str):
        name = self.store.username_for(sender_pub) if self.store else None
        pane = self._ensure_chat(sender_pub, name)
        pane.append_incoming(text)
        it = self._chat_item_by_pub.get(sender_pub)
        if it:
            it.setText((name or sender_pub[:8] + "…") + " • new")
            row = self.chats.row(it)
            if row > 0:
                self.chats.takeItem(row)
                self.chats.insertItem(0, it)
                self.chats.setCurrentRow(0)

    def _on_select_chat(self, row: int):
        if row < 0: return
        pub = self.chats.item(row).data(Qt.UserRole)
        self._show_chat(pub)
        it = self._chat_item_by_pub.get(pub)
        if it:
            it.setText(self.store.username_for(pub) or pub[:8] + "…")

    def _on_admin_toggle(self, state):
        if self.node:
            self.node.admin_mode = (state == Qt.Checked)

    # ── register / start ──
    @asyncSlot()
    async def _on_register_clicked(self):
        uname = self.user_edit.text().strip()
        if not uname:
            self.log.append("Pick a username first.")
            return
        if self.node:
            await self.stop_node()

        self.cfg_path, cfg, ident, address = ensure_initialized(profile=uname)
        self.addr_value.setText(address)

        def _delivered_cb(m):
            self.bridge.delivered.emit(m["sender_pub"], m["text"], m["id"])

        self.node = Node(self.cfg_path, on_delivered=_delivered_cb)
        self.node.username = uname
        self.node.admin_mode = True
        self.store = self.node.store

        await self.node.start()
        self.log.append(f"Registered and started as '{uname}'.")
        self._refresh_people()
        asyncio.create_task(self._auto_refresh())

        # If box is already checked, enable Tor once here (no duplicate calls)
        if self.tor_check.isChecked():
            await self._set_tor(True)

    # ── start chat ──
    def _start_chat_with_pub(self, pub: str):
        uname = self.store.username_for(pub) if self.store else None
        self._ensure_chat(pub, uname)
        self._show_chat(pub)

    def _on_people_double_clicked(self, item: QListWidgetItem):
        pub = item.data(Qt.UserRole)
        self._start_chat_with_pub(pub)

    def _on_start_chat_clicked(self):
        it = self.people.currentItem()
        if not it:
            self.log.append("Pick someone in People first.")
            return
        self._start_chat_with_pub(it.data(Qt.UserRole))

    # ── Safety (Tor) ──
    def _on_tor_toggled(self, checked: bool):
        asyncio.ensure_future(self._set_tor(checked))

    async def _set_tor(self, checked: bool):
        if not self.node:
            self.log.append("Start the node first (Register / Start).")
            self.tor_check.blockSignals(True)
            self.tor_check.setChecked(False)
            self.tor_check.blockSignals(False)
            return

        # no-op if state already matches (prevents spam)
        if checked == self.tor_active:
            return

        if checked:
            if getattr(self.tor, "enabling", False):
                return
            try:
                prof_dir = os.path.dirname(self.cfg_path) if self.cfg_path else os.getcwd()
                socks_uri = await self.tor.start(prof_dir)
                self.node.set_safety_mode(True, socks_uri)
                self.tor_active = True
                self.log.append(f"Safety mode: ON ({socks_uri})")
            except Exception as e:
                self.log.append(f"Failed to start Tor: {e}")
                self.tor_check.blockSignals(True)
                self.tor_check.setChecked(False)
                self.tor_check.blockSignals(False)
        else:
            if self.tor_active:
                self.node.set_safety_mode(False, None)
                await self.tor.stop()
                self.tor_active = False
                self.log.append("Safety mode: OFF")

# ───────────────────────── run ─────────────────────────

async def main():
    app = QApplication(sys.argv)
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)
    win = MainWindow(); win.show()
    asyncio.ensure_future(win.start_node())
    with loop:
        loop.run_forever()

if __name__ == "__main__":
    asyncio.run(main())
