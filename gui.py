#the Tkinter window and all the button logic

import threading
import tkinter as tk
from tkinter import scrolledtext

from utils import is_valid_url, normalize_url, save_result_to_file
from detector import run_all_checks
from scoring import calculate_local_score, get_final_verdict, format_results
from virustotal import scan_url_virustotal
from config import APP_TITLE, APP_WIDTH, APP_HEIGHT, RESULTS_FILE


# colour scheme - dark theme
BG         = "#1e1e2e"
PANEL      = "#2a2a3e"
ACCENT     = "#7c3aed"
TEXT       = "#e2e8f0"
MUTED      = "#94a3b8"
INPUT_BG   = "#0f0f1a"
BORDER     = "#3b3b5c"

VERDICT_COLOURS = {
    "SAFE":       "#22c55e",
    "SUSPICIOUS": "#f59e0b",
    "PHISHING":   "#ef4444",
}


class PhishingLinkAnalyzer:

    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry(f"{APP_WIDTH}x{APP_HEIGHT}")
        self.root.configure(bg=BG)
        self.root.resizable(False, False)

        self.scan_history = []  # just stored in memory for the session

        self._build_ui()

    def _build_ui(self):

        # --- title bar ---
        title_frame = tk.Frame(self.root, bg=ACCENT, pady=12)
        title_frame.pack(fill="x")

        tk.Label(
            title_frame,
            text="🔍  Phishing URL Detector",
            bg=ACCENT, fg="white",
            font=("Helvetica", 16, "bold")
        ).pack()

        tk.Label(
            title_frame,
            text="Heuristics + VirusTotal combined analysis",
            bg=ACCENT, fg="#ddd6fe",
            font=("Helvetica", 9)
        ).pack()

        # --- url input row ---
        input_frame = tk.Frame(self.root, bg=PANEL, padx=20, pady=15)
        input_frame.pack(fill="x", padx=10, pady=(10, 0))

        tk.Label(
            input_frame,
            text="Enter URL to scan:",
            bg=PANEL, fg=MUTED,
            font=("Helvetica", 9)
        ).pack(anchor="w")

        row = tk.Frame(input_frame, bg=PANEL)
        row.pack(fill="x", pady=(4, 0))

        self.url_entry = tk.Entry(
            row,
            font=("Courier", 11),
            bg=INPUT_BG, fg=TEXT,
            insertbackground=TEXT,
            relief="flat", bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=ACCENT
        )
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 8))
        self.url_entry.bind("<Return>", lambda e: self._start_scan())

        self.scan_btn = tk.Button(
            row,
            text="Scan URL",
            command=self._start_scan,
            bg=ACCENT, fg="white",
            font=("Helvetica", 10, "bold"),
            relief="flat", padx=14, pady=6,
            cursor="hand2",
            activebackground="#6d28d9",
            activeforeground="white"
        )
        self.scan_btn.pack(side="left", padx=(0, 6))

        self.clear_btn = tk.Button(
            row,
            text="Clear",
            command=self._clear_all,
            bg=PANEL, fg=MUTED,
            font=("Helvetica", 10),
            relief="flat", padx=10, pady=6,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground=BORDER,
            activebackground=BG,
            activeforeground=TEXT
        )
        self.clear_btn.pack(side="left")

        # --- status message ---
        status_frame = tk.Frame(self.root, bg=BG)
        status_frame.pack(fill="x", padx=10, pady=(6, 0))

        self.status_var = tk.StringVar(value="Enter a URL and click Scan")
        self.status_label = tk.Label(
            status_frame,
            textvariable=self.status_var,
            bg=BG, fg=MUTED,
            font=("Helvetica", 9, "italic")
        )
        self.status_label.pack(anchor="w", padx=4)

        # --- verdict badge (hidden until scan runs) ---
        verdict_frame = tk.Frame(self.root, bg=BG)
        verdict_frame.pack(fill="x", padx=10, pady=(4, 0))

        self.verdict_var = tk.StringVar(value="")
        self.verdict_label = tk.Label(
            verdict_frame,
            textvariable=self.verdict_var,
            bg=BG, fg=BG,   # invisible at start
            font=("Helvetica", 14, "bold")
        )
        self.verdict_label.pack(anchor="w", padx=4)

        # --- results text box ---
        results_frame = tk.Frame(self.root, bg=BG)
        results_frame.pack(fill="both", expand=True, padx=10, pady=(6, 6))

        tk.Label(
            results_frame,
            text="Analysis Report:",
            bg=BG, fg=MUTED,
            font=("Helvetica", 9)
        ).pack(anchor="w", padx=4)

        self.results_box = scrolledtext.ScrolledText(
            results_frame,
            font=("Courier", 10),
            bg=INPUT_BG, fg=TEXT,
            insertbackground=TEXT,
            relief="flat", bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            state="disabled",
            wrap="word",
            padx=10, pady=8
        )
        self.results_box.pack(fill="both", expand=True, pady=(4, 0))

        # --- footer ---
        footer = tk.Frame(self.root, bg=BG, pady=4)
        footer.pack(fill="x")
        tk.Label(
            footer,
            text="Results auto-saved to last_scan.txt",
            bg=BG, fg=BORDER,
            font=("Helvetica", 8)
        ).pack()


    def _start_scan(self):
        url = self.url_entry.get().strip()

        if not url:
            self._set_status("Please enter a URL first.", colour="#f59e0b")
            return

        if not is_valid_url(url):
            self._set_status("Invalid URL - make sure it starts with http:// or https://", colour="#ef4444")
            return

        self.scan_btn.config(state="disabled", text="Scanning...")
        self._set_status("Running checks...", colour=MUTED)
        self._clear_results()
        self.verdict_label.config(fg=BG)  #hide old verdict

        #run the scan in a thread so the window stays responsive
        t = threading.Thread(target=self._run_scan, args=(url,), daemon=True)
        t.start()

    def _run_scan(self, url):
        url = normalize_url(url)

        checks = run_all_checks(url)
        local_score, indicators = calculate_local_score(checks)

        # update status before the slow VT call
        self.root.after(0, lambda: self._set_status("Checking VirusTotal...", colour=MUTED))
        vt_results = scan_url_virustotal(url)

        verdict = get_final_verdict(local_score, vt_results)
        report  = format_results(url, indicators, local_score, vt_results, verdict)

        save_result_to_file(report, RESULTS_FILE)

        self.scan_history.append({"url": url, "verdict": verdict, "score": local_score})

        self.root.after(0, lambda: self._show_results(report, verdict))

    def _show_results(self, report, verdict):
        self.results_box.config(state="normal")
        self.results_box.delete("1.0", "end")
        self.results_box.insert("end", report)
        self.results_box.config(state="disabled")

        colour = VERDICT_COLOURS.get(verdict, TEXT)
        self.verdict_var.set(f"  ● VERDICT: {verdict}  ")
        self.verdict_label.config(fg="white", bg=colour)

        self._set_status("✓ Scan complete. Saved to last_scan.txt", colour="#22c55e")
        self.scan_btn.config(state="normal", text="Scan URL")

    def _clear_all(self):
        self.url_entry.delete(0, "end")
        self._clear_results()
        self.verdict_var.set("")
        self.verdict_label.config(bg=BG, fg=BG)
        self._set_status("Enter a URL and click Scan", colour=MUTED)
        self.scan_btn.config(state="normal", text="Scan URL")

    def _clear_results(self):
        self.results_box.config(state="normal")
        self.results_box.delete("1.0", "end")
        self.results_box.config(state="disabled")

    def _set_status(self, msg, colour=None):
        self.status_var.set(msg)
        if colour:
            self.status_label.config(fg=colour)