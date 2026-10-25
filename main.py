"""
IP Finder (mobile) - Kivy app.

Finds a website's IP addresses using in-app versions of 15 recon tools.
Use only on domains you own or have written permission to test.
"""

import re
import threading

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.metrics import dp, sp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.checkbox import CheckBox
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.progressbar import ProgressBar
from kivy.uix.scrollview import ScrollView
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.textinput import TextInput
from kivy.utils import escape_markup

import core

Window.softinput_mode = "below_target"  # keep the text field visible above the keyboard

MAX_LOG_LINES = 400


class ScrollLabel(ScrollView):
    """A scrollable, wrapping, markup-enabled text area."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.label = Label(text="", markup=True, size_hint_y=None, halign="left", valign="top",
                           padding=(dp(8), dp(8)), font_size=sp(13))
        self.label.bind(
            width=lambda *_: setattr(self.label, "text_size", (self.label.width, None)),
            texture_size=lambda *_: setattr(self.label, "height", self.label.texture_size[1]),
        )
        self.add_widget(self.label)

    def set_text(self, text):
        self.label.text = text


def wrap_label(text, **kw):
    lab = Label(text=text, halign="left", valign="middle", **kw)
    lab.bind(size=lambda w, s: setattr(w, "text_size", s))
    return lab


class IPFinderApp(App):
    title = "IP Finder"

    def build(self):
        self.stop_event = threading.Event()
        self.running = False
        self.agg = core.Aggregator()
        self.log_lines = []
        self.done = 0
        self.total = 1
        self.tool_sel = {n: True for n in core.TOOL_ORDER}

        root = BoxLayout(orientation="vertical", padding=dp(8), spacing=dp(6))

        root.add_widget(Label(text="[b]IP Finder[/b]", markup=True, font_size=sp(22),
                              size_hint_y=None, height=dp(36)))

        self.domain_in = TextInput(hint_text="example.com", multiline=False, size_hint_y=None,
                                   height=dp(46), font_size=sp(16), write_tab=False,
                                   input_type="text", keyboard_suggestions=False)
        self.domain_in.bind(on_text_validate=lambda *_: self.start())
        root.add_widget(self.domain_in)

        consent = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(6))
        self.consent_cb = CheckBox(size_hint_x=None, width=dp(44))
        consent.add_widget(self.consent_cb)
        consent.add_widget(wrap_label("I own this domain or have written permission to test it",
                                      font_size=sp(12)))
        root.add_widget(consent)

        row = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(6))
        self.start_btn = Button(text="Start", on_release=lambda *_: self.start())
        self.stop_btn = Button(text="Stop", disabled=True, on_release=lambda *_: self.stop())
        self.tools_btn = Button(text="Tools (15)", on_release=lambda *_: self.open_tools())
        for b in (self.start_btn, self.stop_btn, self.tools_btn):
            row.add_widget(b)
        root.add_widget(row)

        self.progress = ProgressBar(max=1, value=0, size_hint_y=None, height=dp(10))
        root.add_widget(self.progress)
        self.status = wrap_label("Ready.", size_hint_y=None, height=dp(34), font_size=sp(12))
        root.add_widget(self.status)

        self.tabs = TabbedPanel(do_default_tab=False, tab_height=dp(36), tab_width=dp(88))
        self.ips_view = ScrollLabel()
        self.subs_view = ScrollLabel()
        self.tools_view = ScrollLabel()
        self.log_view = ScrollLabel()
        first = None
        for name, view in (("IPs", self.ips_view), ("Subs", self.subs_view),
                           ("Tools", self.tools_view), ("Log", self.log_view)):
            item = TabbedPanelItem(text=name)
            item.add_widget(view)
            self.tabs.add_widget(item)
            first = first or item
        self.tabs.switch_to(first)
        root.add_widget(self.tabs)

        bottom = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(6))
        bottom.add_widget(Button(text="Copy IPs", on_release=lambda *_: self.copy_ips()))
        bottom.add_widget(Button(text="Copy report", on_release=lambda *_: self.copy_report()))
        bottom.add_widget(Button(text="Clear", on_release=lambda *_: self.clear()))
        root.add_widget(bottom)

        self.render_all()
        return root

    def on_pause(self):
        return True  # keep the scan alive when the app is sent to the background

    # ---------------- actions ----------------
    def start(self):
        if self.running:
            return
        domain = re.sub(r"^https?://", "", self.domain_in.text.strip().lower()).split("/")[0]
        if not core.DOMAIN_RE.match(domain):
            self.status.text = "Invalid domain. Example: example.com"
            return
        if not self.consent_cb.active:
            self.status.text = "Tick the permission checkbox first."
            return
        selected = [n for n, v in self.tool_sel.items() if v]
        if not selected:
            self.status.text = "Select at least one tool."
            return

        self.clear(keep_domain=True)
        self.domain_in.text = domain
        self.agg = core.Aggregator(domain)
        self.stop_event.clear()
        self.done, self.total = 0, len(selected)
        self.progress.max, self.progress.value = self.total, 0
        self.status.text = f"Running {self.total} tool(s) against {domain}..."
        self.add_log(f"[*] Target: {domain}")
        self.set_running(True)

        def emit(event, payload):
            Clock.schedule_once(lambda dt, e=event, p=payload: self.handle(e, p))

        threading.Thread(target=core.run_scan, daemon=True,
                         args=(domain, set(selected), self.stop_event, emit)).start()

    def stop(self):
        if self.running:
            self.stop_event.set()
            self.status.text = "Stopping..."
            self.add_log("[!] Stop requested")

    def clear(self, keep_domain=False):
        if self.running:
            return
        self.agg = core.Aggregator()
        self.log_lines = []
        self.done, self.progress.value = 0, 0
        if not keep_domain:
            self.domain_in.text = ""
            self.status.text = "Ready."
        self.render_all()

    def set_running(self, running):
        self.running = running
        self.start_btn.disabled = running
        self.stop_btn.disabled = not running
        self.tools_btn.disabled = running

    def copy_ips(self):
        if not self.agg.main_ips:
            self.status.text = "No IPs to copy yet."
            return
        Clipboard.copy("\n".join(sorted(self.agg.main_ips)))
        self.status.text = f"Copied {len(self.agg.main_ips)} IP(s) to the clipboard."

    def copy_report(self):
        if not self.agg.results:
            self.status.text = "Nothing to copy yet."
            return
        Clipboard.copy(self.agg.report())
        self.status.text = "Report copied to the clipboard."

    # ---------------- events ----------------
    def handle(self, event, payload):
        if event == "log":
            self.add_log(payload)
        elif event == "stage":
            self.status.text = payload
        elif event == "tool_done":
            self.done += 1
            self.progress.value = min(self.done, self.total)
            self.agg.add(payload)
            self.add_log(f"[+] {payload['tool']}: {payload['status']}")
            self.status.text = f"Completed {self.done}/{self.total}: {payload['tool']}"
            self.render_all()
        elif event == "final":
            self.agg.set_resolved(payload["subdomains"], payload["related_map"])
            self.set_running(False)
            self.progress.value = self.total
            n = len(self.agg.main_ips)
            if payload["cancelled"]:
                self.status.text = "Stopped. Partial results shown."
            elif self.agg.notes:
                self.status.text = f"Done. {n} main IP(s). Note: CDN detected (see IPs tab)."
            else:
                self.status.text = f"Done. {n} main IP(s), {len(self.agg.subdomains)} subdomain(s)."
            self.add_log("[*] Finished")
            self.render_all()

    # ---------------- rendering ----------------
    def add_log(self, line):
        self.log_lines.append(line)
        self.log_lines = self.log_lines[-MAX_LOG_LINES:]
        self.log_view.set_text("\n".join(escape_markup(x) for x in self.log_lines))

    def render_all(self):
        a = self.agg
        # IPs tab
        out = ["[b]Main IPs[/b]  (more tools agreeing = more reliable)"]
        if a.main_ips:
            for ip, t in sorted(a.main_ips.items(), key=lambda x: (-len(x[1]), x[0])):
                out.append(f"[b]{escape_markup(ip)}[/b]\n   {len(t)} tool(s): "
                           f"{escape_markup(', '.join(sorted(t)))}")
        else:
            out.append("none yet")
        rel = a.related_ips()
        if rel:
            out += ["", "[b]Other related IPs[/b] (nameservers, mail, subdomains, CDN)",
                    escape_markup(", ".join(rel))]
        for note in sorted(a.notes):
            out += ["", "[color=ffaa00][b]Note:[/b] " + escape_markup(note) + "[/color]"]
        self.ips_view.set_text("\n".join(out))

        # Subdomains tab
        out = [f"[b]Subdomains[/b] ({len(a.subdomains)})"]
        out += [f"{escape_markup(h)}\n   {escape_markup(', '.join(i))}"
                for h, i in sorted(a.subdomains.items())] or ["none yet"]
        if a.related_map:
            out += ["", f"[b]Nameserver / mail hosts[/b] ({len(a.related_map)})"]
            out += [f"{escape_markup(h)}\n   {escape_markup(', '.join(i))}"
                    for h, i in sorted(a.related_map.items())]
        self.subs_view.set_text("\n".join(out))

        # Tools tab
        out = ["[b]Tool status[/b]"]
        for name in core.TOOL_ORDER:
            r = a.results.get(name)
            if r:
                color = "66cc66" if r["status"] == "ok" else "ffaa00"
                out.append(f"[b]{name}[/b]  [color={color}]{escape_markup(r['status'])}[/color]\n"
                           f"   {escape_markup(r['info'])}")
        if len(out) == 1:
            out.append("none yet")
        self.tools_view.set_text("\n".join(out))

        self.log_view.set_text("\n".join(escape_markup(x) for x in self.log_lines))

    # ---------------- tool picker ----------------
    def open_tools(self):
        grid = GridLayout(cols=1, size_hint_y=None, spacing=dp(4))
        grid.bind(minimum_height=grid.setter("height"))
        boxes = {}
        for name in core.TOOL_ORDER:
            row = BoxLayout(size_hint_y=None, height=dp(48))
            cb = CheckBox(active=self.tool_sel[name], size_hint_x=None, width=dp(44))
            cb.bind(active=lambda w, v, n=name: self.tool_sel.__setitem__(n, v))
            boxes[name] = cb
            row.add_widget(cb)
            row.add_widget(wrap_label(f"[b]{name}[/b]  {core.TOOL_INFO[name]}", markup=True,
                                      font_size=sp(12)))
            grid.add_widget(row)
        sv = ScrollView()
        sv.add_widget(grid)

        def set_all(value):
            for cb in boxes.values():
                cb.active = value

        buttons = BoxLayout(size_hint_y=None, height=dp(46), spacing=dp(6))
        buttons.add_widget(Button(text="All", on_release=lambda *_: set_all(True)))
        buttons.add_widget(Button(text="None", on_release=lambda *_: set_all(False)))
        box = BoxLayout(orientation="vertical", spacing=dp(6))
        box.add_widget(sv)
        box.add_widget(buttons)
        popup = Popup(title="Select tools", content=box, size_hint=(0.95, 0.9))
        buttons.add_widget(Button(text="Done", on_release=lambda *_: popup.dismiss()))
        popup.bind(on_dismiss=lambda *_: setattr(
            self.tools_btn, "text", f"Tools ({sum(self.tool_sel.values())})"))
        popup.open()


if __name__ == "__main__":
    IPFinderApp().run()
