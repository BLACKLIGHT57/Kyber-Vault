import tkinter as tk
from tkinter import ttk, messagebox
import threading, os, sys

sys.path.insert(0, os.path.dirname(__file__))
from kyber_vault import KyberVault, generate_password

# ═══════════════════════════════════════════════════════════════════
#  ТЕМЫ
# ═══════════════════════════════════════════════════════════════════

THEMES = {
    "light": {
        "bg":       "#d3dce8",
        "surface":  "#ffffff",
        "panel":    "#f0f2f5",
        "border":   "#dde2ea",
        "accent":   "#2563eb",
        "accent2":  "#16a34a",
        "warn":     "#dc2626",
        "text":     "#1e293b",
        "muted":    "#64748b",
        "sel_bg":   "#dbeafe",
        "sel_fg":   "#1e40af",
        "entry_bg": "#ffffff",
        "list_bg":  "#ffffff",
        "icon":     "🌙",
        "icon_lbl": "Тёмная тема",
    },
    "dark": {
        "bg":       "#080c10",
        "surface":  "#0d1318",
        "panel":    "#111820",
        "border":   "#1e2d3d",
        "accent":   "#00d4ff",
        "accent2":  "#00ff9f",
        "warn":     "#ff4d6d",
        "text":     "#c8d8e8",
        "muted":    "#4a6070",
        "sel_bg":   "#0a2030",
        "sel_fg":   "#00d4ff",
        "entry_bg": "#0a1520",
        "list_bg":  "#0d1318",
        "icon":     "☀️",
        "icon_lbl": "Светлая тема",
    },
}

FONT_MONO   = ("Courier New", 10)
FONT_MONO_S = ("Courier New", 9)
FONT_SANS_B = ("Segoe UI", 13, "bold")
FONT_SANS   = ("Segoe UI", 10)
FONT_SANS_S = ("Segoe UI", 9)
FONT_TITLE  = ("Segoe UI", 18, "bold")
FONT_H2     = ("Segoe UI", 12, "bold")
FONT_LABEL  = ("Segoe UI", 9)

VAULT_DIR = os.path.join(os.path.dirname(__file__), "vaults")
os.makedirs(VAULT_DIR, exist_ok=True)

# ── Глобальная тема ───────────────────────────────────────────────
C = dict(THEMES["light"])

def apply_theme(name: str):
    C.update(THEMES[name])

# ── Определение системной темы ────────────────────────────────────
def detect_system_theme() -> str:
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        )
        val, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return "light" if val == 1 else "dark"
    except Exception:
        pass
    try:
        import subprocess
        r = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"],
                           capture_output=True, text=True)
        return "dark" if "Dark" in r.stdout else "light"
    except Exception:
        pass
    return "light"


# ═══════════════════════════════════════════════════════════════════
#  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ═══════════════════════════════════════════════════════════════════

def mk_btn(parent, text, command, color_key="accent", width=16,
           small=False, bg_key="panel"):
    fg   = C[color_key]
    bg   = C[bg_key]
    font = FONT_SANS_S if small else FONT_SANS
    b = tk.Button(
        parent, text=text, command=command,
        bg=bg, fg=fg, font=font,
        relief="flat", bd=0,
        padx=10, pady=4 if small else 7,
        activebackground=C["border"], activeforeground=fg,
        cursor="hand2", width=width,
        highlightthickness=1, highlightbackground=C["border"],
    )
    b.bind("<Enter>", lambda e: b.config(bg=C["border"]))
    b.bind("<Leave>", lambda e: b.config(bg=bg))
    return b

def mk_entry(parent, show=None, width=30, readonly=False):
    bg = C["panel"] if readonly else C["entry_bg"]
    e = tk.Entry(
        parent,
        bg=bg, fg=C["text"],
        font=FONT_MONO, relief="flat",
        insertbackground=C["accent"],
        selectbackground=C["accent"],
        selectforeground=C["bg"],
        readonlybackground=C["panel"],
        width=width, show=show or "",
        state="readonly" if readonly else "normal",
        highlightthickness=1,
        highlightbackground=C["border"],
        highlightcolor=C["accent"],
    )
    return e

def mk_sep(parent):
    return tk.Frame(parent, bg=C["border"], height=1)

def mk_space(parent, h=8, bg_key="bg"):
    return tk.Frame(parent, bg=C[bg_key], height=h)

def mk_label(parent, text, color_key="muted", font=None,
             anchor="w", bg_key="bg"):
    return tk.Label(parent, text=text,
                    bg=C[bg_key], fg=C[color_key],
                    font=font or FONT_LABEL, anchor=anchor)


# ═══════════════════════════════════════════════════════════════════
#  ДИАЛОГ АВТОРИЗАЦИИ
# ═══════════════════════════════════════════════════════════════════

class AuthDialog(tk.Toplevel):
    def __init__(self, parent, mode="open", vault_names=None):
        super().__init__(parent)
        self.result = None
        self.mode   = mode
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.grab_set()
        self.title("Открыть хранилище" if mode=="open" else "Создать хранилище")

        h = 360 if mode == "open" else 400
        self.geometry(f"400x{h}")
        self.update_idletasks()
        x = parent.winfo_x() + parent.winfo_width()  // 2 - 200
        y = parent.winfo_y() + parent.winfo_height() // 2 - h // 2
        self.geometry(f"+{x}+{y}")

        self._build(vault_names or [])
        self.bind("<Return>", lambda e: self._submit())
        self.bind("<Escape>", lambda e: self.destroy())

    def _build(self, vaults):
        pad = dict(padx=24, pady=0)

        tk.Label(self, text="🔐  Kyber Vault",
                 bg=C["bg"], fg=C["accent"],
                 font=("Segoe UI", 16, "bold")).pack(pady=(24, 4))
        tk.Label(self, text="Kyber-CPA · Module-LWE · FIPS 203",
                 bg=C["bg"], fg=C["muted"],
                 font=FONT_SANS_S).pack(pady=(0, 16))
        mk_sep(self).pack(fill="x", **pad)
        mk_space(self, 14).pack()

        if self.mode == "open" and vaults:
            mk_label(self, "Хранилище").pack(**pad, anchor="w")
            mk_space(self, 4).pack()
            self.combo = ttk.Combobox(self, values=vaults,
                                      state="readonly", font=FONT_MONO, width=28)
            self._style_combo()
            self.combo.pack(**pad, fill="x")
            if vaults: self.combo.current(0)
            mk_space(self, 12).pack()
        else:
            mk_label(self, "Имя хранилища").pack(**pad, anchor="w")
            mk_space(self, 4).pack()
            self.name_entry = mk_entry(self, width=30)
            self.name_entry.pack(**pad, fill="x")
            mk_space(self, 12).pack()

        mk_label(self, "Мастер-пароль").pack(**pad, anchor="w")
        mk_space(self, 4).pack()
        self.pwd_entry = mk_entry(self, show="•", width=30)
        self.pwd_entry.pack(**pad, fill="x")
        self.pwd_entry.focus_set()

        if self.mode == "create":
            mk_space(self, 10).pack()
            mk_label(self, "Подтверждение пароля").pack(**pad, anchor="w")
            mk_space(self, 4).pack()
            self.pwd2_entry = mk_entry(self, show="•", width=30)
            self.pwd2_entry.pack(**pad, fill="x")

        mk_space(self, 18).pack()
        lbl = "Открыть" if self.mode == "open" else "Создать"
        mk_btn(self, lbl, self._submit,
               color_key="accent2", width=30).pack(**pad, fill="x")

    def _style_combo(self):
        s = ttk.Style(self)
        s.theme_use("default")
        s.configure("TCombobox",
                    fieldbackground=C["entry_bg"],
                    background=C["panel"],
                    foreground=C["text"],
                    selectbackground=C["sel_bg"],
                    selectforeground=C["text"],
                    bordercolor=C["border"],
                    arrowcolor=C["accent"])
        # Явно задаём цвет текста через map для всех состояний
        s.map("TCombobox",
              foreground=[("readonly", C["text"]),
                          ("disabled", C["muted"]),
                          ("active",   C["text"]),
                          ("!disabled", C["text"])],
              fieldbackground=[("readonly", C["entry_bg"]),
                               ("!disabled", C["entry_bg"])],
              selectforeground=[("focus", C["text"]),
                                ("!focus", C["text"])])
        # Текст в поле combo
        self.combo.configure(foreground=C["text"])

    def _submit(self):
        pwd = self.pwd_entry.get()
        if not pwd:
            messagebox.showerror("Ошибка", "Введите пароль", parent=self); return
        if self.mode == "open":
            name = self.combo.get() if hasattr(self, "combo") else ""
            if not name:
                messagebox.showerror("Ошибка", "Выберите хранилище", parent=self); return
            self.result = (name, pwd)
        else:
            name = self.name_entry.get().strip()
            pwd2 = self.pwd2_entry.get()
            if not name:
                messagebox.showerror("Ошибка", "Введите имя", parent=self); return
            if len(pwd) < 8:
                messagebox.showerror("Ошибка", "Минимум 8 символов", parent=self); return
            if pwd != pwd2:
                messagebox.showerror("Ошибка", "Пароли не совпадают", parent=self); return
            if os.path.exists(os.path.join(VAULT_DIR, name + ".kybr")):
                messagebox.showerror("Ошибка", "Имя уже занято", parent=self); return
            self.result = (name, pwd)
        self.destroy()


# ═══════════════════════════════════════════════════════════════════
#  ДИАЛОГ ДОБАВИТЬ / ИЗМЕНИТЬ
# ═══════════════════════════════════════════════════════════════════

class EntryDialog(tk.Toplevel):
    def __init__(self, parent, entry=None):
        super().__init__(parent)
        self.result = None
        self.entry  = entry
        self.configure(bg=C["bg"])
        self.resizable(False, False)
        self.grab_set()
        self.title("Новая запись" if not entry else "Изменить запись")

        self.geometry("460x530")
        self.update_idletasks()
        x = parent.winfo_x() + parent.winfo_width()  // 2 - 230
        y = parent.winfo_y() + parent.winfo_height() // 2 - 265
        self.geometry(f"+{x}+{y}")
        self._build()
        self.bind("<Escape>", lambda e: self.destroy())

    def _build(self):
        pad = dict(padx=24, pady=0)
        e   = self.entry or {}

        tk.Label(self, text="Новая запись" if not self.entry else "Изменить запись",
                 bg=C["bg"], fg=C["accent"],
                 font=FONT_H2).pack(padx=24, pady=(20, 14), anchor="w")
        mk_sep(self).pack(fill="x", **pad)
        mk_space(self, 12).pack()

        # Сервис
        mk_label(self, "Сервис / Сайт").pack(**pad, anchor="w")
        mk_space(self, 4).pack()
        self.f_svc = mk_entry(self, width=36)
        self.f_svc.insert(0, e.get("service", ""))
        self.f_svc.pack(**pad, fill="x")
        if self.entry: self.f_svc.config(state="disabled")
        mk_space(self, 10).pack()

        # Логин
        mk_label(self, "Логин / Email").pack(**pad, anchor="w")
        mk_space(self, 4).pack()
        self.f_login = mk_entry(self, width=36)
        self.f_login.insert(0, e.get("login", ""))
        self.f_login.pack(**pad, fill="x")
        mk_space(self, 10).pack()

        # Пароль
        mk_label(self, "Пароль").pack(**pad, anchor="w")
        mk_space(self, 4).pack()
        pwd_row = tk.Frame(self, bg=C["bg"])
        pwd_row.pack(**pad, fill="x")
        self.f_pwd = mk_entry(pwd_row, show="•", width=28)
        self.f_pwd.insert(0, e.get("password", ""))
        self.f_pwd.pack(side="left", fill="x", expand=True)
        self._pwd_vis = False
        def toggle_pwd():
            self._pwd_vis = not self._pwd_vis
            self.f_pwd.config(show="" if self._pwd_vis else "•")
            eye.config(text="🙈" if self._pwd_vis else "👁")
        eye = tk.Button(pwd_row, text="👁", command=toggle_pwd,
                        bg=C["panel"], fg=C["muted"],
                        font=("Segoe UI Emoji", 11), relief="flat",
                        bd=0, padx=8, cursor="hand2",
                        activebackground=C["border"])
        eye.pack(side="left", padx=(4, 0))
        mk_space(self, 10).pack()

        # Генератор
        gen = tk.LabelFrame(self, text="  Генератор паролей  ",
                             bg=C["panel"], fg=C["muted"],
                             font=FONT_SANS_S, bd=1, relief="solid",
                             highlightbackground=C["border"])
        gen.pack(**pad, fill="x")
        self.gen_var = tk.StringVar(value="")
        tk.Label(gen, textvariable=self.gen_var,
                 bg=C["entry_bg"], fg=C["accent2"],
                 font=FONT_MONO, anchor="w",
                 width=34, pady=6, padx=8).pack(fill="x", padx=8, pady=(8, 4))

        ctrl = tk.Frame(gen, bg=C["panel"])
        ctrl.pack(fill="x", padx=8, pady=(0, 6))
        tk.Label(ctrl, text="Длина:", bg=C["panel"],
                 fg=C["muted"], font=FONT_SANS_S).pack(side="left")
        self.len_var = tk.IntVar(value=20)
        self.len_lbl = tk.Label(ctrl, text="20", bg=C["panel"],
                                 fg=C["accent"], font=FONT_MONO_S, width=3)
        self.len_lbl.pack(side="left")
        ttk.Scale(ctrl, from_=8, to=64, variable=self.len_var,
                  orient="horizontal", length=70,
                  command=lambda v: self.len_lbl.config(
                      text=str(int(float(v))))).pack(side="left", padx=(2, 8))
        self.up_var  = tk.BooleanVar(value=True)
        self.dig_var = tk.BooleanVar(value=True)
        self.sym_var = tk.BooleanVar(value=True)
        for lbl, var in [("A-Z", self.up_var), ("0-9", self.dig_var), ("!@#", self.sym_var)]:
            tk.Checkbutton(ctrl, text=lbl, variable=var,
                           bg=C["panel"], fg=C["text"],
                           font=FONT_SANS_S, selectcolor=C["bg"],
                           activebackground=C["panel"],
                           activeforeground=C["accent"]).pack(side="left", padx=2)

        gr = tk.Frame(gen, bg=C["panel"])
        gr.pack(fill="x", padx=8, pady=(0, 8))
        mk_btn(gr, "Сгенерировать", self._gen_pwd,
               color_key="accent", width=14, small=True,
               bg_key="panel").pack(side="left", padx=(0, 6))
        mk_btn(gr, "Использовать", self._use_gen,
               color_key="accent2", width=14, small=True,
               bg_key="panel").pack(side="left")

        mk_space(self, 10).pack()
        mk_label(self, "Заметки").pack(**pad, anchor="w")
        mk_space(self, 4).pack()
        self.f_notes = tk.Text(self, bg=C["entry_bg"], fg=C["text"],
                                font=FONT_SANS_S, relief="flat",
                                insertbackground=C["accent"],
                                height=3, width=40,
                                highlightthickness=1,
                                highlightbackground=C["border"],
                                highlightcolor=C["accent"])
        self.f_notes.insert("1.0", e.get("notes", ""))
        self.f_notes.pack(**pad, fill="x")

        mk_space(self, 14).pack()
        mk_sep(self).pack(fill="x", **pad)
        mk_space(self, 10).pack()
        bar = tk.Frame(self, bg=C["bg"])
        bar.pack(**pad, fill="x")
        mk_btn(bar, "💾  Сохранить", self._submit,
               color_key="accent2", width=14).pack(side="left", padx=(0, 8))
        mk_btn(bar, "Отмена", self.destroy,
               color_key="muted", width=10).pack(side="left")

        (self.f_svc if not self.entry else self.f_login).focus_set()

    def _gen_pwd(self):
        self.gen_var.set(generate_password(
            length=int(self.len_var.get()),
            upper=self.up_var.get(),
            digits=self.dig_var.get(),
            symbols=self.sym_var.get(),
        ))

    def _use_gen(self):
        pwd = self.gen_var.get()
        if not pwd:
            messagebox.showinfo("Генератор", "Сначала нажмите «Сгенерировать»",
                                parent=self); return
        self.f_pwd.delete(0, "end")
        self.f_pwd.insert(0, pwd)
        self.f_pwd.config(show="")
        self._pwd_vis = True

    def _submit(self):
        svc   = self.f_svc.get().strip()
        login = self.f_login.get().strip()
        pwd   = self.f_pwd.get()
        notes = self.f_notes.get("1.0", "end-1c").strip()
        if not svc:
            messagebox.showerror("Ошибка", "Укажите сервис", parent=self); return
        self.result = {"service": svc, "login": login,
                       "password": pwd, "notes": notes}
        self.destroy()


# ═══════════════════════════════════════════════════════════════════
#  ГЛАВНОЕ ОКНО
# ═══════════════════════════════════════════════════════════════════

class KyberVaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Kyber Vault  ·  ML-KEM Kyber-512")
        self.geometry("940x650")
        self.minsize(760, 540)

        self.vault:      KyberVault | None = None
        self.master_pwd: str  = ""
        self.vault_name: str  = ""
        self.entries:    list = []
        self.selected:   str | None = None
        self._filtered:  list = []

        # Светлая тема по умолчанию, потом детектим систему
        self._theme = detect_system_theme()
        apply_theme(self._theme)
        self.configure(bg=C["bg"])

        self._build_ui()
        self._show_welcome()

    # ── Переключение темы ─────────────────────────────────────────

    def _toggle_theme(self):
        self._theme = "light" if self._theme == "dark" else "dark"
        apply_theme(self._theme)
        for w in self.winfo_children():
            w.destroy()
        self.configure(bg=C["bg"])
        self._build_ui()
        if self.vault:
            # Восстанавливаем название хранилища в шапке
            self.vault_lbl.config(text=f"🔓  {self.vault_name.upper()}")
            self._show_vault()
            self._refresh_entries()
            if self.selected:
                e = next((x for x in self.entries if x["service"] == self.selected), None)
                if e: self._show_entry(e)
        else:
            self._show_welcome()

    # ── Построение UI ─────────────────────────────────────────────

    def _build_ui(self):
        # Topbar
        topbar = tk.Frame(self, bg=C["surface"], height=54)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")

        tk.Label(topbar, text="🔐  Kyber Vault",
                 bg=C["surface"], fg=C["accent"],
                 font=("Segoe UI", 13, "bold")).pack(side="left", padx=20)
        tk.Label(topbar, text="Kyber-CPA · Module-LWE · FIPS 203",
                 bg=C["surface"], fg=C["muted"],
                 font=FONT_SANS_S).pack(side="left", padx=8)

        # Кнопка темы
        self._theme_btn = tk.Button(
            topbar,
            text=f"{C['icon']}  {C['icon_lbl']}",
            command=self._toggle_theme,
            bg=C["panel"], fg=C["muted"],
            font=FONT_SANS_S, relief="flat", bd=0,
            padx=12, pady=5, cursor="hand2",
            activebackground=C["border"],
            highlightthickness=1, highlightbackground=C["border"],
        )
        self._theme_btn.pack(side="right", padx=14)
        self._theme_btn.bind("<Enter>",
            lambda e: self._theme_btn.config(fg=C["accent"]))
        self._theme_btn.bind("<Leave>",
            lambda e: self._theme_btn.config(fg=C["muted"]))

        self.vault_lbl = tk.Label(topbar, text="",
                                   bg=C["surface"], fg=C["accent2"],
                                   font=FONT_SANS_S)
        self.vault_lbl.pack(side="right", padx=4)

        # Body
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True)

        # Sidebar
        self.sidebar = tk.Frame(body, bg=C["surface"], width=245)
        self.sidebar.pack_propagate(False)

        sb_head = tk.Frame(self.sidebar, bg=C["surface"])
        sb_head.pack(fill="x")
        tk.Label(sb_head, text="Записи", bg=C["surface"],
                 fg=C["muted"], font=FONT_LABEL).pack(side="left", padx=14, pady=10)
        self.count_lbl = tk.Label(sb_head, text="", bg=C["surface"],
                                   fg=C["accent"], font=FONT_MONO_S)
        self.count_lbl.pack(side="right", padx=14)
        tk.Frame(self.sidebar, bg=C["border"], height=1).pack(fill="x")

        # Поиск
        sf = tk.Frame(self.sidebar, bg=C["surface"], pady=8, padx=10)
        sf.pack(fill="x")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._filter_entries())
        tk.Entry(sf, textvariable=self.search_var,
                 bg=C["entry_bg"], fg=C["text"],
                 font=FONT_SANS_S, relief="flat",
                 insertbackground=C["accent"],
                 highlightthickness=1,
                 highlightbackground=C["border"],
                 highlightcolor=C["accent"]).pack(fill="x", ipady=5)
        tk.Frame(self.sidebar, bg=C["border"], height=1).pack(fill="x")

        # Список
        lf = tk.Frame(self.sidebar, bg=C["surface"])
        lf.pack(fill="both", expand=True)
        sb = tk.Scrollbar(lf, bg=C["border"], troughcolor=C["surface"],
                          relief="flat", bd=0, width=5)
        self.listbox = tk.Listbox(
            lf, bg=C["list_bg"], fg=C["text"],
            font=FONT_SANS_S,
            selectbackground=C["sel_bg"],
            selectforeground=C["sel_fg"],
            relief="flat", bd=0, activestyle="none",
            highlightthickness=0,
            yscrollcommand=sb.set,
        )
        sb.config(command=self.listbox.yview)
        sb.pack(side="right", fill="y")
        self.listbox.pack(fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)
        self.listbox.bind("<Double-Button-1>", lambda e: self._edit_entry())

        tk.Frame(self.sidebar, bg=C["border"], height=1).pack(fill="x")

        sbf = tk.Frame(self.sidebar, bg=C["surface"], pady=8, padx=10)
        sbf.pack(fill="x")
        mk_btn(sbf, "+ Добавить запись", self._add_entry,
               color_key="accent2", width=18, small=True,
               bg_key="surface").pack(fill="x", pady=(0, 4))
        mk_btn(sbf, "Сменить хранилище", self._change_vault,
               color_key="muted", width=18, small=True,
               bg_key="surface").pack(fill="x", pady=(0, 4))
        mk_btn(sbf, "🗑  Удалить хранилище", self._delete_vault,
               color_key="warn", width=18, small=True,
               bg_key="surface").pack(fill="x")

        tk.Frame(body, bg=C["border"], width=1).pack(side="left", fill="y")

        # Правая панель
        self.content = tk.Frame(body, bg=C["bg"])
        self.content.pack(side="left", fill="both", expand=True)

        self.panel_welcome = tk.Frame(self.content, bg=C["bg"])
        self._build_welcome(self.panel_welcome)

        self.panel_detail = tk.Frame(self.content, bg=C["bg"])
        self._build_detail(self.panel_detail)

    # ── Экран приветствия ─────────────────────────────────────────

    def _build_welcome(self, parent):
        inner = tk.Frame(parent, bg=C["bg"])
        inner.place(relx=.5, rely=.5, anchor="center")

        tk.Label(inner, text="🔐", bg=C["bg"], fg=C["accent"],
                 font=("Segoe UI Emoji", 52)).pack(pady=(0, 10))
        tk.Label(inner, text="Kyber Vault",
                 bg=C["bg"], fg=C["accent"],
                 font=FONT_TITLE).pack()
        tk.Label(inner,
                 text="Система защиты информации на основе диофантовых уравнений",
                 bg=C["bg"], fg=C["muted"],
                 font=FONT_SANS_S).pack(pady=(4, 24))

        # Таблица алгоритмов
        info = tk.Frame(inner, bg=C["panel"],
                        highlightthickness=1,
                        highlightbackground=C["border"])
        info.pack(fill="x", padx=20, pady=(0, 24))
        rows = [
            ("Шифрование данных",    "Kyber-CPA (Module-LWE)",   "accent"),
            ("Управление ключами",   "ML-KEM Kyber-512",          "accent"),
            ("Стандарт",             "FIPS 203 · NIST 2024",      "accent"),
            ("Защита мастер-пароля", "PBKDF2-SHA256 · 600k",      "accent"),
            ("Целостность файла",    "HMAC-SHA256",               "accent"),
            ("Квантовая стойкость",  "✓ Post-Quantum Safe",       "accent2"),
        ]
        for i, (k, v, vc) in enumerate(rows):
            bg = C["panel"] if i % 2 == 0 else C["surface"]
            row = tk.Frame(info, bg=bg)
            row.pack(fill="x")
            tk.Label(row, text=k, bg=bg, fg=C["muted"],
                     font=FONT_LABEL, width=26, anchor="w",
                     padx=14, pady=7).pack(side="left")
            tk.Label(row, text=v, bg=bg, fg=C[vc],
                     font=FONT_LABEL, anchor="w",
                     padx=14).pack(side="left")

        btn_row = tk.Frame(inner, bg=C["bg"])
        btn_row.pack()
        mk_btn(btn_row, "Открыть хранилище", self._open_vault,
               color_key="accent", width=20).pack(side="left", padx=(0, 10))
        mk_btn(btn_row, "Создать новое", self._create_vault,
               color_key="accent2", width=16).pack(side="left")

    # ── Панель деталей ────────────────────────────────────────────

    def _build_detail(self, parent):
        self.detail_frame = tk.Frame(parent, bg=C["bg"])
        self.detail_frame.pack(fill="both", expand=True, padx=36, pady=28)

        # Заголовок записи
        head = tk.Frame(self.detail_frame, bg=C["bg"])
        head.pack(fill="x", pady=(0, 4))

        self.d_icon_lbl = tk.Label(head, text="",
                                    bg=C["accent"], fg="#ffffff",
                                    font=("Segoe UI", 18, "bold"),
                                    width=3, pady=6)
        self.d_icon_lbl.pack(side="left", padx=(0, 14))

        head_r = tk.Frame(head, bg=C["bg"])
        head_r.pack(side="left", fill="x", expand=True)
        self.d_service = tk.Label(head_r, text="",
                                   bg=C["bg"], fg=C["text"],
                                   font=("Segoe UI", 16, "bold"), anchor="w")
        self.d_service.pack(fill="x")
        self.d_sub = tk.Label(head_r, text="",
                               bg=C["bg"], fg=C["muted"],
                               font=FONT_SANS_S, anchor="w")
        self.d_sub.pack(fill="x")

        act = tk.Frame(head, bg=C["bg"])
        act.pack(side="right")
        mk_btn(act, "✏️  Изменить", self._edit_entry,
               color_key="accent", width=12, small=True).pack(side="left", padx=(0, 6))
        mk_btn(act, "🗑  Удалить", self._delete_entry,
               color_key="warn", width=11, small=True).pack(side="left")

        mk_sep(self.detail_frame).pack(fill="x", pady=14)

        # Поля логин / пароль
        def add_field(label, attr, secret=False):
            lf = tk.Frame(self.detail_frame, bg=C["bg"])
            lf.pack(fill="x", pady=(0, 12))
            tk.Label(lf, text=label, bg=C["bg"],
                     fg=C["muted"], font=FONT_LABEL).pack(anchor="w")
            mk_space(lf, 3).pack()
            row = tk.Frame(lf, bg=C["bg"])
            row.pack(fill="x")
            val = tk.Entry(row,
                           bg=C["panel"], fg=C["text"],
                           font=FONT_MONO, relief="flat",
                           state="readonly",
                           readonlybackground=C["panel"],
                           show="•" if secret else "",
                           highlightthickness=1,
                           highlightbackground=C["border"])
            val.pack(side="left", fill="x", expand=True, ipady=6)
            setattr(self, attr, val)

            if secret:
                _vis = [False]
                def make_eye(v=val):
                    def toggle():
                        _vis[0] = not _vis[0]
                        v.config(show="" if _vis[0] else "•")
                        btn.config(text="🙈" if _vis[0] else "👁")
                    return toggle
                btn = tk.Button(row, text="👁", command=make_eye(),
                                bg=C["panel"], fg=C["muted"],
                                font=("Segoe UI Emoji", 11),
                                relief="flat", bd=0, padx=8, pady=6,
                                cursor="hand2",
                                activebackground=C["border"])
                btn.pack(side="left", padx=(2, 2))

            def make_copy(v=val, lbl=label):
                def do():
                    self.clipboard_clear()
                    self.clipboard_append(v.get())
                    self._flash(f"✓ {lbl} скопирован")
                return do

            tk.Button(row, text="Копировать",
                      command=make_copy(),
                      bg=C["panel"], fg=C["muted"],
                      font=FONT_SANS_S, relief="flat",
                      bd=0, padx=10, pady=6,
                      cursor="hand2",
                      activebackground=C["border"],
                      activeforeground=C["accent2"]).pack(side="left", padx=(2, 0))

        add_field("Логин / Email", "d_login")
        add_field("Пароль", "d_password", secret=True)

        tk.Label(self.detail_frame, text="Заметки",
                 bg=C["bg"], fg=C["muted"], font=FONT_LABEL).pack(anchor="w")
        mk_space(self.detail_frame, 3).pack()
        self.d_notes = tk.Text(self.detail_frame,
                                bg=C["panel"], fg=C["text"],
                                font=FONT_SANS_S, relief="flat",
                                state="disabled", height=4,
                                highlightthickness=1,
                                highlightbackground=C["border"])
        self.d_notes.pack(fill="x", pady=(0, 16))

        # Плашка безопасности — ИСПРАВЛЕНА
        sec = tk.Frame(self.detail_frame, bg=C["panel"],
                       highlightthickness=1,
                       highlightbackground=C["border"])
        sec.pack(fill="x")
        for k, v in [
            ("Шифрование данных",  "✓ Kyber-CPA (Module-LWE / диофантовы уравнения)"),
            ("Управление ключами", "✓ ML-KEM Kyber-512 (FIPS 203)"),
            ("Целостность",        "✓ HMAC-SHA256"),
        ]:
            r = tk.Frame(sec, bg=C["panel"])
            r.pack(fill="x")
            tk.Label(r, text=k, bg=C["panel"], fg=C["muted"],
                     font=FONT_LABEL, width=20, anchor="w",
                     padx=14, pady=5).pack(side="left")
            tk.Label(r, text=v, bg=C["panel"], fg=C["accent2"],
                     font=FONT_LABEL, anchor="w").pack(side="left")

        self.status_lbl = tk.Label(self.detail_frame, text="",
                                    bg=C["bg"], fg=C["accent2"],
                                    font=FONT_SANS_S, anchor="w")
        self.status_lbl.pack(fill="x", pady=(10, 0))

    # ── Навигация ─────────────────────────────────────────────────

    def _show_welcome(self):
        self.panel_detail.pack_forget()
        self.panel_welcome.pack(fill="both", expand=True)
        self.sidebar.pack_forget()
        self.vault_lbl.config(text="")

    def _show_vault(self):
        self.panel_welcome.pack_forget()
        self.sidebar.pack(side="left", fill="y")
        self.panel_detail.pack(fill="both", expand=True)
        if not self.selected:
            self._clear_detail()

    def _clear_detail(self):
        self.d_icon_lbl.pack_forget()
        self.d_service.config(text="Выберите запись")
        self.d_sub.config(text="из списка слева")
        for attr in ("d_login", "d_password"):
            w = getattr(self, attr, None)
            if w:
                w.config(state="normal"); w.delete(0, "end")
                w.config(state="readonly", show="•" if attr == "d_password" else "")
        self.d_notes.config(state="normal")
        self.d_notes.delete("1.0", "end")
        self.d_notes.config(state="disabled")

    # ── Vault ops ─────────────────────────────────────────────────

    def _open_vault(self):
        vaults = [f[:-5] for f in os.listdir(VAULT_DIR) if f.endswith(".kybr")]
        if not vaults:
            messagebox.showinfo("Нет хранилищ", "Создайте новое хранилище")
            self._create_vault(); return
        dlg = AuthDialog(self, mode="open", vault_names=vaults)
        self.wait_window(dlg)
        if not dlg.result: return
        self._load_threaded(*dlg.result)

    def _create_vault(self):
        dlg = AuthDialog(self, mode="create")
        self.wait_window(dlg)
        if not dlg.result: return
        self._create_threaded(*dlg.result)

    def _change_vault(self):
        if messagebox.askyesno("Сменить хранилище", "Закрыть текущее хранилище?"):
            self.vault = None; self.entries = []; self.selected = None
            self._show_welcome()

    def _delete_vault(self):
        if not self.vault:
            messagebox.showinfo("", "Сначала откройте хранилище"); return
        name = self.vault_name
        path = os.path.join(VAULT_DIR, name + ".kybr")
        if not messagebox.askyesno(
            "Удалить хранилище",
            f"Безопасно удалить хранилище «{name}»?\n\n"
            "Файл будет перезаписан 3 раза и удалён.\n"
            "Восстановление невозможно!"
        ): return
        if not messagebox.askyesno(
            "Подтверждение",
            f"Вы уверены? Хранилище «{name}» будет удалено безвозвратно."
        ): return

        from kyber_vault import secure_delete
        ok = secure_delete(path)
        if ok:
            messagebox.showinfo("Готово",
                f"Хранилище «{name}» безопасно удалено.\n"
                "Файл перезаписан 3 раза случайными байтами.")
            self.vault = None
            self.entries = []
            self.selected = None
            self._show_welcome()
        else:
            messagebox.showerror("Ошибка", "Не удалось удалить файл хранилища.")

    def _load_threaded(self, name, pwd):
        def task():
            v = KyberVault()
            try:
                v.load(os.path.join(VAULT_DIR, name + ".kybr"), pwd)
                self.after(0, lambda: self._on_loaded(v, name, pwd))
            except Exception as e:
                self.after(0, lambda err=str(e): messagebox.showerror("Ошибка", err))
        threading.Thread(target=task, daemon=True).start()

    def _create_threaded(self, name, pwd):
        def task():
            v = KyberVault()
            try:
                v.create(pwd)
                v.save(os.path.join(VAULT_DIR, name + ".kybr"), pwd)
                self.after(0, lambda: self._on_loaded(v, name, pwd))
            except Exception as e:
                self.after(0, lambda err=str(e): messagebox.showerror("Ошибка", err))
        threading.Thread(target=task, daemon=True).start()

    def _on_loaded(self, v, name, pwd):
        self.vault      = v
        self.vault_name = name
        self.master_pwd = pwd
        self.entries    = []
        self.selected   = None
        self.vault_lbl.config(text=f"🔓  {name.upper()}")
        self._refresh_entries()
        self._show_vault()
        self._clear_detail()

    # ── Список записей ────────────────────────────────────────────

    def _refresh_entries(self):
        if not self.vault: return
        self.entries = [{"service": s, **self.vault.get_entry(s)}
                        for s in self.vault.list_services()]
        self._filter_entries()
        self.count_lbl.config(text=str(len(self.entries)))

    def _filter_entries(self):
        q = self.search_var.get().lower()
        self._filtered = [
            e for e in self.entries
            if q in e["service"].lower() or q in e["login"].lower()
        ] if q else list(self.entries)

        self.listbox.delete(0, "end")
        for e in self._filtered:
            self.listbox.insert("end", f"  {e['service'][0].upper()}  {e['service']}")

        if self.selected:
            for i, e in enumerate(self._filtered):
                if e["service"] == self.selected:
                    self.listbox.selection_set(i); break

    def _on_select(self, event):
        sel = self.listbox.curselection()
        if not sel: return
        idx = sel[0]
        if idx >= len(self._filtered): return
        self.selected = self._filtered[idx]["service"]
        self._show_entry(self._filtered[idx])

    def _show_entry(self, entry):
        icon = entry["service"][0].upper()
        self.d_icon_lbl.config(text=icon, bg=C["accent"])
        self.d_icon_lbl.pack(side="left", padx=(0, 14))
        self.d_service.config(text=entry["service"])
        self.d_sub.config(text=entry.get("login", ""))
        self._set_ro(self.d_login, entry.get("login", ""))
        self._set_ro(self.d_password, entry.get("password", ""))
        self.d_password.config(show="•")
        self.d_notes.config(state="normal")
        self.d_notes.delete("1.0", "end")
        self.d_notes.insert("1.0", entry.get("notes", ""))
        self.d_notes.config(state="disabled")

    def _set_ro(self, widget, value):
        widget.config(state="normal"); widget.delete(0, "end")
        widget.insert(0, value); widget.config(state="readonly")

    # ── CRUD ─────────────────────────────────────────────────────

    def _add_entry(self):
        if not self.vault:
            messagebox.showinfo("", "Сначала откройте хранилище"); return
        dlg = EntryDialog(self)
        self.wait_window(dlg)
        if not dlg.result: return
        r = dlg.result
        self.vault.add_entry(r["service"], r["login"], r["password"], r["notes"])
        self._save_vault()
        self.selected = r["service"]
        self._refresh_entries()
        self._show_entry(r)
        self._flash(f"✓ Запись «{r['service']}» добавлена")

    def _edit_entry(self):
        if not self.selected: return
        entry = next((e for e in self.entries if e["service"] == self.selected), None)
        if not entry: return
        dlg = EntryDialog(self, entry=entry)
        self.wait_window(dlg)
        if not dlg.result: return
        r = dlg.result
        self.vault.add_entry(self.selected, r["login"], r["password"], r["notes"])
        self._save_vault()
        self._refresh_entries()
        updated = next((e for e in self.entries if e["service"] == self.selected), r)
        self._show_entry(updated)
        self._flash(f"✓ Запись «{self.selected}» обновлена")

    def _delete_entry(self):
        if not self.selected: return
        if not messagebox.askyesno("Удалить", f"Удалить «{self.selected}»?"): return
        self.vault.delete_entry(self.selected)
        self._save_vault()
        self.selected = None
        self._refresh_entries()
        self._clear_detail()
        self._flash("✓ Запись удалена")

    def _save_vault(self):
        self.vault.save(
            os.path.join(VAULT_DIR, self.vault_name + ".kybr"),
            self.master_pwd
        )

    def _flash(self, msg):
        self.status_lbl.config(text=msg, fg=C["accent2"])
        self.after(3000, lambda: self.status_lbl.config(text=""))


# ═══════════════════════════════════════════════════════════════════
#  ТОЧКА ВХОДА
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = KyberVaultApp()
    app.mainloop()
