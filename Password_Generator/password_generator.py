import tkinter as tk
from tkinter import ttk, filedialog
import secrets
import string
import sys
import argparse
import time
import math  # Required for entropy calculation
import json
import os  # For checking if history file exists
import hashlib # NEW: For SHA-1 hashing
from urllib.request import urlopen, Request # NEW: For HIBP API access
from urllib.error import URLError

# --- Configuration Constants ---

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
ADVANCED_SYMBOLS = '!@#$%^&*()_+=-[]{};:.,<>/?`~'
# Define characters commonly confused when read/typed
AMBIGUOUS_CHARS = set('0OolI1S5Z2z|{}[]()/\'"`~,.;:')
HISTORY_FILE = "password_history.json"
MAX_HISTORY = 10

# Enhanced Modern Theme Palette
THEMES = {
    "dark": {
        "bg_main": "#0D1117",  # Deep dark (like GitHub)
        "fg_text": "#C9D1D9",  # Light gray for standard text
        "bg_secondary": "#161B22",  # Slightly lighter dark for secondary elements/cards
        "primary": "#58A6FF",  # Vibrant blue/teal accent
        "success": "#3FB950",  # Green
        "medium": "#FCD34D",  # Yellow/Amber
        "danger": "#F85149",  # Red
        "trough": "#21262D",  # Dark gray for progress bar trough/border
        "border_color": "#30363D"  # Subtle border for separation
    },
    "light": {
        "bg_main": "#f7f9fb",
        "fg_text": "#1f2937",
        "bg_secondary": "#ffffff",
        "primary": "#1e73be",
        "success": "#27ae60",
        "medium": "#d35400",
        "danger": "#c0392b",
        "trough": "#e6e6e6",
        "border_color": "#d1d5db"
    }
}
DEFAULT_FONT = ('Inter', 12)

# --- Core Security Functions (Unchanged for logic) ---

def calculate_entropy(length, pool_size):
    """Calculates estimated password entropy (in bits)."""
    if pool_size <= 1 or length <= 0:
        return 0
    return length * math.log2(pool_size)


def get_char_pool(lowercase, uppercase, digits, symbols, avoid_ambiguous=False):
    """
    Constructs the character pool based on user selections.
    Includes logic to remove ambiguous characters if requested.
    """
    char_sets = []
    if lowercase:
        char_sets.append(LOWERCASE)
    if uppercase:
        char_sets.append(UPPERCASE)
    if digits:
        char_sets.append(DIGITS)
    if symbols:
        char_sets.append(ADVANCED_SYMBOLS)

    char_pool = "".join(char_sets)

    if avoid_ambiguous:
        char_pool = "".join(c for c in char_pool if c not in AMBIGUOUS_CHARS)

    char_pool = "".join(sorted(list(set(char_pool))))
    return char_pool, len(char_sets)


def generate_secure_password(length, char_pool, char_sets, prevent_repetition=False):
    """Generates a cryptographically secure password with optional constraints."""
    if not char_pool or length <= 0:
        return "Error: Empty character pool or length."

    password = []
    # Guarantee at least one char from each selected set
    for char_set in char_sets:
        filtered_set = "".join(c for c in char_set if c in char_pool)
        if filtered_set:
            password.append(secrets.choice(filtered_set))

    remaining_length = length - len(password)
    last_char = None

    for _ in range(remaining_length):
        temp_pool = char_pool
        if prevent_repetition and last_char:
            temp_pool = temp_pool.replace(last_char, '')
            if not temp_pool:
                temp_pool = char_pool
        if not temp_pool:
            break
        next_char = secrets.choice(temp_pool)
        password.append(next_char)
        last_char = next_char

    secrets.SystemRandom().shuffle(password)
    return "".join(password)


def evaluate_strength_score(length, pool_size):
    """Returns a score (0-100) and strength text based on entropy."""
    entropy = calculate_entropy(length, pool_size)

    if entropy < 60:
        score = int(entropy / 60 * 33)  # 0 to 33
        text = "Weak"
    elif entropy < 90:
        score = int(33 + (entropy - 60) / 30 * 33)  # 33 to 66
        text = "Medium"
    elif entropy < 128: # Add "Good" tier for higher score
        score = int(66 + (entropy - 90) / 38 * 24)  # 66 to 90 (128 bits is the standard target)
        text = "Good"
    else:
        score = int(90 + (entropy - 128) / 40 * 10) # 90 to 100
        text = "Strong"

    return min(100, score), text, entropy


# --- Component Frames ---


class StrengthCheckerFrame(ttk.Frame):
    """Dedicated frame for live/manual password strength testing."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.theme = controller.current_theme

        header = ttk.Frame(self, style="TFrame")
        header.pack(fill='x', pady=(10, 6), padx=10)
        ttk.Label(header, text="🧠 Live Password Strength Tester", font=('Inter', 18, 'bold')).pack(side='left', anchor='w')
        
        # Input field - uses custom styling
        self.typed_pass_field = tk.Entry(self, font=('Courier New', 16), relief='flat', show="*",
                                         bg=self.theme["bg_secondary"], fg=self.theme["fg_text"], insertbackground=self.theme["fg_text"],
                                         highlightthickness=2, highlightcolor=self.theme["border_color"])
        self.typed_pass_field.pack(fill='x', ipady=12, padx=10, pady=(6, 12))
        self.typed_pass_field.bind('<KeyRelease>', self._live_preview_score)

        # Buttons row: Check + Reveal + Breach Check
        row = ttk.Frame(self, style="TFrame")
        row.pack(fill='x', pady=(0, 10), padx=10)
        
        self.check_btn = ttk.Button(row, text="🔎 Check Strength", command=self.live_strength_check, style="Primary.TButton")
        self.check_btn.pack(side='left', padx=(0, 12))

        self.reveal_var = tk.BooleanVar(value=False)
        self.reveal_btn = ttk.Button(row, text="👁 Reveal", command=self._toggle_reveal, style="TButton")
        self.reveal_btn.pack(side='left', padx=(0, 12))

        # NEW: Breach Check Button
        self.breach_check_btn = ttk.Button(row, text="⚠️ Check Breach Status", command=self.run_breach_check, style="Danger.TButton")
        self.breach_check_btn.pack(side='left')

        # Strength Feedback
        feedback_frame = ttk.Frame(self, style="TFrame")
        feedback_frame.pack(fill='x', pady=(8, 6), padx=10)
        
        self.live_strength_label = ttk.Label(feedback_frame, text="Enter password to check.", font=('Inter', 14, 'bold'))
        self.live_strength_label.pack(side='left')
        self.live_entropy_label = ttk.Label(feedback_frame, text="Entropy: 0.00 bits", font=('Inter', 12))
        self.live_entropy_label.pack(side='right')

        self.live_strength_bar = ttk.Progressbar(self, orient='horizontal', length=100, mode='determinate', style="TProgressbar")
        self.live_strength_bar.pack(fill='x', padx=10, pady=(6, 15))

        # Suggestions area
        ttk.Label(self, text="Suggestions for Improvement:", font=('Inter', 14, 'bold'), foreground=self.theme["primary"]).pack(pady=(8, 4), anchor='w', padx=10)
        
        self.suggestions_text = tk.Text(self, height=7, relief='flat', wrap=tk.WORD, state='disabled',
                                        bg=self.theme["bg_secondary"], fg=self.theme["fg_text"],
                                        font=('Inter', 11), highlightthickness=1, highlightbackground=self.theme["trough"])
        self.suggestions_text.pack(fill='x', padx=10, pady=(0, 10))

        # NEW: Breach Status Display
        ttk.Label(self, text="Breach Database Status:", font=('Inter', 14, 'bold')).pack(pady=(8, 4), anchor='w', padx=10)
        self.breach_status_label = ttk.Label(self, text="Status: Ready to check.", font=('Inter', 12, 'bold'), anchor='w')
        self.breach_status_label.pack(fill='x', padx=10, pady=(0, 10))

        # Add micro-animation when checking
        self._animating = False

    def _toggle_reveal(self):
        if self.reveal_var.get():
            self.typed_pass_field.config(show="*")
            self.reveal_btn.config(text="👁 Reveal")
            self.reveal_var.set(False)
        else:
            self.typed_pass_field.config(show="")
            self.reveal_btn.config(text="🙈 Hide")
            self.reveal_var.set(True)

    def _live_preview_score(self, event=None):
        """Live preview but low-priority - doesn't commit suggestions until Check pressed."""
        typed_pass = self.typed_pass_field.get()
        length = len(typed_pass)
        typed_chars = set(typed_pass)
        pool_size = 0
        has_lower = any(c in LOWERCASE for c in typed_chars)
        has_upper = any(c in UPPERCASE for c in typed_chars)
        has_digit = any(c in DIGITS for c in typed_chars)
        has_symbol = any(c in ADVANCED_SYMBOLS for c in typed_chars)
        if has_lower: pool_size += len(LOWERCASE)
        if has_upper: pool_size += len(UPPERCASE)
        if has_digit: pool_size += len(DIGITS)
        if has_symbol: pool_size += len(ADVANCED_SYMBOLS)
        score, strength_text, entropy = evaluate_strength_score(length, pool_size)
        
        color_key = {"Weak": "danger", "Medium": "medium", "Good": "primary", "Strong": "success"}.get(strength_text, "primary")
        color = self.theme[color_key]
        
        self.live_strength_label.config(text=f"Preview: {strength_text} | Score: {score}%", foreground=color)
        self.live_entropy_label.config(text=f"Entropy: {entropy:.2f} bits", foreground=color)
        self.live_strength_bar.config(value=score, style=f"{strength_text}.Horizontal.TProgressbar")

    def live_strength_check(self, event=None):
        """Analyzes strength and entropy for a manually typed password (explicit Check)."""
        if self._animating:
            return  # avoid overlapping animations
        typed_pass = self.typed_pass_field.get()
        theme = self.controller.current_theme

        if not typed_pass:
            self.live_strength_label.config(text="Enter password to check.", foreground=theme["fg_text"])
            self.live_entropy_label.config(text="Entropy: 0.00 bits", foreground=theme["fg_text"])
            self.live_strength_bar.config(value=0, style="TProgressbar")
            self._update_suggestions([])
            self.breach_status_label.config(text="Status: Ready to check.", foreground=theme["fg_text"])
            return

        length = len(typed_pass)
        typed_chars = set(typed_pass)

        pool_size = 0
        suggestions = []
        has_lower = any(c in LOWERCASE for c in typed_chars)
        has_upper = any(c in UPPERCASE for c in typed_chars)
        has_digit = any(c in DIGITS for c in typed_chars)
        has_symbol = any(c in ADVANCED_SYMBOLS for c in typed_chars)

        if has_lower:
            pool_size += len(LOWERCASE)
        else:
            suggestions.append("❌ Add lowercase letters.")
        if has_upper:
            pool_size += len(UPPERCASE)
        else:
            suggestions.append("❌ Add uppercase letters.")
        if has_digit:
            pool_size += len(DIGITS)
        else:
            suggestions.append("❌ Add digits (0-9).")
        if has_symbol:
            pool_size += len(ADVANCED_SYMBOLS)
        else:
            suggestions.append("❌ Add symbols (!@#...).")

        if length < 16:
            suggestions.append(f"⬆️ Increase length (currently {length}). Aim for 16+ for modern security.")
        if length < 12:
            suggestions.append(f"⚠️ Length is too short (must be 12+).")

        score, strength_text, entropy = evaluate_strength_score(length, pool_size)

        color_key = {"Weak": "danger", "Medium": "medium", "Good": "primary", "Strong": "success"}.get(strength_text, "primary")
        color = theme[color_key]
        self.live_strength_label.config(text=f"Strength: {strength_text} | Score: {score}%", foreground=color)
        self.live_entropy_label.config(text=f"Entropy: {entropy:.2f} bits", foreground=color)
        
        self.live_strength_bar.config(style=f"{strength_text}.Horizontal.TProgressbar")
        self._animate_bar_to(score)

        if strength_text == "Strong":
            self._update_suggestions(["✅ This password looks strong and secure!"])
        else:
            self._update_suggestions(suggestions)

    def _animate_bar_to(self, target):
        """Simple smooth animation for the bar value."""
        self._animating = True
        current = self.live_strength_bar['value']
        step = 1 if target > current else -1

        def step_fn():
            nonlocal current
            if current == target:
                self._animating = False
                return
            
            # Simple linear step to target
            current = current + step
            if (step > 0 and current > target) or (step < 0 and current < target):
                current = target
                
            self.live_strength_bar.config(value=current)
            self.after(6, step_fn)  # small delay for smoothness

        step_fn()

    def _update_suggestions(self, suggestions):
        self.suggestions_text.config(state='normal')
        self.suggestions_text.delete(1.0, tk.END)
        self.suggestions_text.insert(tk.END, "\n".join(suggestions))
        self.suggestions_text.config(state='disabled')
        
    def run_breach_check(self):
        password = self.typed_pass_field.get()
        theme = self.controller.current_theme
        
        if not password or "ERROR" in password:
            self.breach_status_label.config(text="Cannot check: Password field is empty.", foreground=theme["danger"])
            return

        # Show loading state instantly
        self.breach_status_label.config(text="⏳ Checking breach database...", foreground=theme["medium"])

        # Call the non-blocking checker with a callback
        self.controller.master.after(100, lambda: self.controller.check_breach_status(password, self.handle_breach_result))
    
    def handle_breach_result(self, count):
        theme = self.controller.current_theme
        
        if count is None:
            self.breach_status_label.config(text="⚠️ Error connecting to breach service.", foreground=theme["danger"])
        elif count == 0:
            self.breach_status_label.config(text="✅ This password has not appeared in any known breaches.", foreground=theme["success"])
        else:
            text = f"🔴 WARNING: This password appeared in {count:,} known breaches. DO NOT USE."
            self.breach_status_label.config(text=text, foreground=theme["danger"])


class HistoryFrame(ttk.Frame):
    """Dedicated frame for displaying password history."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        ttk.Label(self, text="📋 Recent Passwords History", font=('Inter', 18, 'bold')).pack(pady=(10, 8), anchor='w', padx=10)

        # Reuse canvas + inner frame for vertical scrolling
        self.history_canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0, bg=self.controller.current_theme["bg_main"])
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.history_canvas.yview)
        self.history_canvas.configure(yscrollcommand=self.scrollbar.set)

        self.scrollbar.pack(side="right", fill="y")
        self.history_canvas.pack(side="left", fill="both", expand=True, padx=6, pady=6)

        self.scrollable_frame = ttk.Frame(self.history_canvas, padding="5", style="TFrame")
        self.scrollable_window = self.history_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        self.scrollable_frame.bind("<Configure>", lambda e: self.history_canvas.configure(scrollregion=self.history_canvas.bbox("all")))
        self.history_canvas.bind('<Configure>', self._on_canvas_resize)

        self.update_history_display()

    def _on_canvas_resize(self, event):
        self.history_canvas.itemconfig(self.scrollable_window, width=event.width)

    def delete_entry(self, index):
        try:
            del self.controller.password_history[index]
            self.controller.save_history()
            self.update_history_display()
        except IndexError:
            pass

    def update_history_display(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        theme = self.controller.current_theme

        if not self.controller.password_history:
            ttk.Label(self.scrollable_frame, text="No generated passwords yet. Generate in the Generator tab!",
                      font=DEFAULT_FONT, foreground=theme["fg_text"]).pack(padx=20, pady=40)
            return

        # Simplified Header
        header_frame = ttk.Frame(self.scrollable_frame, style="TFrame", padding="8 4")
        header_frame.pack(fill='x', pady=(0, 5))
        ttk.Label(header_frame, text="Timestamp", font=('Inter', 11, 'bold'), width=20, anchor='w').pack(side='left', padx=10)
        ttk.Label(header_frame, text="Password", font=('Inter', 11, 'bold'), anchor='w').pack(side='left', padx=10, fill='x', expand=True)
        ttk.Label(header_frame, text="Actions", font=('Inter', 11, 'bold'), width=22, anchor='w').pack(side='right', padx=5)

        for idx, entry in enumerate(self.controller.password_history):
            password = entry["password"]
            timestamp = entry["timestamp"]
            is_visible_var = tk.BooleanVar(value=False)

            # Styled History Item Card - using Card.TFrame style
            item_frame = ttk.Frame(self.scrollable_frame, padding="10", style="Card.TFrame") 
            item_frame.pack(fill='x', pady=6, padx=6)

            ttk.Label(item_frame, text=timestamp, font=('Courier New', 10), width=20, anchor='w',
                      foreground=theme["primary"]).pack(side='left', padx=6)

            password_var = tk.StringVar(value=password)
            password_entry = tk.Entry(item_frame, textvariable=password_var, font=('Courier New', 14, 'bold'), relief='flat',
                                       state='readonly', readonlybackground=theme["bg_secondary"], fg=theme["fg_text"], width=30)
            password_entry.config(show="*")
            password_entry.pack(side='left', padx=10, fill='x', expand=True, ipady=3)
            
            # Action Buttons
            delete_btn = ttk.Button(item_frame, text="🗑", width=3, command=lambda i=idx: self.delete_entry(i), style="Danger.TButton")
            delete_btn.pack(side='right', padx=4)
            copy_btn = ttk.Button(item_frame, text="📋", width=3, command=lambda p=password: self.controller.copy_to_clipboard(p), style="Success.TButton")
            copy_btn.pack(side='right', padx=4)

            def toggle_vis(var, entry_widget, btn):
                if var.get():
                    entry_widget.config(show="*")
                    btn.config(text="👁")
                    var.set(False)
                else:
                    entry_widget.config(show="")
                    btn.config(text="🙈")
                    var.set(True)

            show_btn = ttk.Button(item_frame, text="👁", width=3, command=lambda v=is_visible_var, e=password_entry, b=None: toggle_vis(v, e, show_btn), style="TButton")
            show_btn.pack(side='right', padx=4)


class GeneratorFrame(ttk.Frame):
    """Dedicated frame for the main password generation controls."""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        theme = controller.current_theme

        ttk.Label(self, text="🔐 Secure Password Generator", font=('Inter', 18, 'bold')).pack(pady=(10, 6), anchor='w', padx=10)

        # OUTPUT DISPLAY AREA (Card-like)
        # Using Card.TFrame style to apply background and border (via ttk relief/borderwidth defined in style)
        output_area_frame = ttk.Frame(self, padding="12", style="Card.TFrame") 
        output_area_frame.pack(fill='x', pady=(8, 12), padx=10)

        self.password_display = tk.Entry(output_area_frame,
                                             font=('Courier New', 20, 'bold'),
                                             justify='center',
                                             relief='flat',
                                             state='readonly',
                                             show='*',
                                             bg=theme["bg_secondary"], fg=theme["fg_text"], 
                                             readonlybackground=theme["bg_secondary"])
        self.password_display.pack(fill='x', padx=10, pady=(6, 8), ipady=12)

        # Strength/Entropy Feedback
        feedback_row = ttk.Frame(output_area_frame, style="TFrame")
        feedback_row.pack(fill='x', pady=(4, 8), padx=10)
        self.strength_label = ttk.Label(feedback_row, text="Strength: Unknown", font=('Inter', 12, 'bold'))
        self.strength_label.pack(side='left')

        self.entropy_label = ttk.Label(feedback_row, text="Entropy: 0.00 bits", font=('Inter', 12))
        self.entropy_label.pack(side='right')

        self.strength_bar = ttk.Progressbar(output_area_frame, orient='horizontal', length=100, mode='determinate', style="TProgressbar")
        self.strength_bar.pack(fill='x', padx=10, pady=(6, 8))
        self.update_strength_bar(0, "Weak")

        # NEW: Breach Status Display
        self.breach_status_label = ttk.Label(output_area_frame, text="Status: Awaiting generation...", font=('Inter', 12, 'bold'), anchor='w')
        self.breach_status_label.pack(fill='x', padx=10, pady=(4, 8))


        # CONTROLS AND CONFIGURATION
        config_frame = ttk.Frame(self, padding="10", style="TFrame")
        config_frame.pack(fill='x', pady=6, padx=10)
        
        # --- Left Section: Length & Sets ---
        config_left_frame = ttk.Frame(config_frame, style="TFrame")
        config_left_frame.pack(side='left', fill='y', expand=True, padx=10)

        ttk.Label(config_left_frame, text="Password Length (8-32):", font=('Inter', 12, 'bold')).pack(anchor='w', pady=(0, 4))
        
        length_display_frame = ttk.Frame(config_left_frame, style="TFrame")
        length_display_frame.pack(fill='x', pady=(0, 8))
        self.length_label = ttk.Label(length_display_frame, text=f"{self.controller.length_var.get()} characters", font=('Inter', 14, 'bold'), foreground=theme["primary"])
        self.length_label.pack(side='left')
        
        self.length_slider = ttk.Scale(length_display_frame, from_=8, to=32, variable=self.controller.length_var, orient='horizontal', command=self._update_length_label)
        self.length_slider.pack(side='right', fill='x', expand=True, padx=(10, 0))

        ttk.Label(config_left_frame, text="Character Sets:", font=('Inter', 12, 'bold')).pack(anchor='w', pady=(10, 4))
        
        set_options = [
            ("Lowercase (a-z)", self.controller.lowercase_var),
            ("Uppercase (A-Z)", self.controller.uppercase_var),
            ("Digits (0-9)", self.controller.digits_var),
            ("Symbols (!@#...)", self.controller.symbols_var)
        ]
        set_cb_frame = ttk.Frame(config_left_frame, style="TFrame")
        set_cb_frame.pack(fill='x', pady=(0, 10))
        
        for text, var in set_options:
            ttk.Checkbutton(set_cb_frame, text=text, variable=var, style="TCheckbutton").pack(anchor='w', pady=2)
            
        # New: Ambiguous Character Constraint
        ttk.Label(config_left_frame, text="Generation Constraints:", font=('Inter', 12, 'bold')).pack(anchor='w', pady=(10, 4))
        ttk.Checkbutton(config_left_frame, 
                        text="Avoid Ambiguous Chars (e.g., 'l', '1', 'I', 'O', '0')", 
                        variable=self.controller.avoid_ambiguous_var, 
                        style="TCheckbutton").pack(anchor='w', pady=2)

        # --- Vertical Separator ---
        ttk.Separator(config_frame, orient='vertical').pack(side='left', fill='y', padx=20, pady=5)
        
        # --- Right Section: Metadata & Actions ---
        config_right_frame = ttk.Frame(config_frame, style="TFrame")
        config_right_frame.pack(side='left', fill='both', expand=True, padx=10)

        ttk.Label(config_right_frame, text="Export Metadata (CSV/TXT)", font=('Inter', 14, 'bold'), foreground=theme["primary"]).pack(anchor='w', pady=(0, 6))
        
        ttk.Label(config_right_frame, text="Site/Service:").pack(anchor='w')
        tk.Entry(config_right_frame, textvariable=self.controller.site_var, font=('Inter', 11), relief='flat',
                  bg=theme["bg_secondary"], fg=theme["fg_text"], insertbackground=theme["fg_text"], highlightthickness=1, highlightcolor=theme["trough"]).pack(fill='x', ipady=3, pady=(0, 8))
        
        ttk.Label(config_right_frame, text="Username/Email:").pack(anchor='w')
        tk.Entry(config_right_frame, textvariable=self.controller.username_var, font=('Inter', 11), relief='flat',
                  bg=theme["bg_secondary"], fg=theme["fg_text"], insertbackground=theme["fg_text"], highlightthickness=1, highlightcolor=theme["trough"]).pack(fill='x', ipady=3, pady=(0, 15))

        # Action Buttons Row
        button_frame = ttk.Frame(config_right_frame, style="TFrame")
        button_frame.pack(fill='x', pady=(10, 0))
        
        self.visibility_button = ttk.Button(button_frame, text="👁 Show", command=self.toggle_password_visibility, style="TButton")
        self.visibility_button.pack(side='right', padx=4)
        
        ttk.Button(button_frame, text="🔑 Generate (Ctrl+G)", command=self.controller.generate_and_display, style="Primary.TButton").pack(side='left', padx=4)
        ttk.Button(button_frame, text="📋 Copy (Ctrl+C)", command=self.controller.copy_to_clipboard, style="TButton").pack(side='left', padx=4)
        ttk.Button(button_frame, text="💾 Save/Export", command=self.controller.save_password_file, style="TButton").pack(side='left', padx=4)

        self.copy_feedback_label = ttk.Label(config_right_frame, text="", font=('Inter', 12, 'bold'))
        self.copy_feedback_label.pack(pady=10)

    def _update_length_label(self, event):
        self.length_label.config(text=f"{int(self.controller.length_var.get())} characters")

    def update_strength_bar(self, score, strength_text):
        theme = self.controller.current_theme
        
        style_name = f"{strength_text}.Horizontal.TProgressbar"

        self.strength_bar.config(style=style_name, value=score)
        
        strength_color_key = {
            "Weak": "danger",
            "Medium": "medium",
            "Good": "primary",
            "Strong": "success"
        }.get(strength_text, "primary")
        
        color = theme[strength_color_key]
        self.strength_label.config(text=f"Strength: {strength_text} | Score: {score}%", foreground=color)

    def toggle_password_visibility(self):
        self.controller.is_password_visible.set(not self.controller.is_password_visible.get())
        if self.controller.is_password_visible.get():
            self.password_display.config(show="")
            self.visibility_button.config(text="🙈 Hide")
        else:
            self.password_display.config(show="*")
            self.visibility_button.config(text="👁 Show")

    def update_display(self, password, entropy):
        self.password_display.config(state='normal')
        self.password_display.delete(0, 'end')
        self.password_display.insert(0, password)
        self.password_display.config(state='readonly', show='*' if not self.controller.is_password_visible.get() else "")
        self.entropy_label.config(text=f"Entropy: {entropy:.2f} bits")

    def show_feedback(self, message, color_key="success"):
        color = self.controller.current_theme[color_key]
        self.copy_feedback_label.config(text=message, foreground=color)
        self.controller.master.after(2000, lambda: self.copy_feedback_label.config(text=""))
        
    def handle_breach_result(self, count):
        theme = self.controller.current_theme
        
        if count is None:
            self.breach_status_label.config(text="⚠️ Error connecting to breach service.", foreground=theme["danger"])
        elif count == 0:
            self.breach_status_label.config(text="✅ This password has not appeared in any known breaches.", foreground=theme["success"])
        else:
            text = f"🔴 WARNING: This password appeared in {count:,} known breaches. DO NOT USE."
            self.breach_status_label.config(text=text, foreground=theme["danger"])


class PasswordGeneratorApp:
    """Main Tkinter application for the secure password generator."""

    def __init__(self, master):
        self.master = master
        master.title("SecureGen | Advanced Password Manager")

        # Global State Variables
        self.is_dark_theme_var = tk.BooleanVar(value=True)
        self.is_password_visible = tk.BooleanVar(value=False)
        self.site_var = tk.StringVar(value="")
        self.username_var = tk.StringVar(value="")
        self.breach_cache = {} # NEW: In-memory cache for HIBP API responses

        # Generation Vars
        self.length_var = tk.IntVar(value=16)
        self.lowercase_var = tk.BooleanVar(value=True)
        self.uppercase_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        self.avoid_ambiguous_var = tk.BooleanVar(value=True) # NEW: Avoid ambiguous characters

        # History & Persistence
        self.password_history = self._load_history()

        self.frames = {}

        # Initial Setup & theming
        self._apply_theme(THEMES["dark"])
        self.master.update_idletasks()

        # Window Geometry & scrolling support
        window_width = 1000
        window_height = 750
        screen_width = master.winfo_screenwidth()
        screen_height = master.winfo_screenheight()
        center_x = int(screen_width / 2 - window_width / 2)
        center_y = int(screen_height / 2 - window_height / 2)
        master.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        master.minsize(650, 500)

        # Build main canvas to allow scrolling if window is small
        self.main_canvas = tk.Canvas(master, borderwidth=0, highlightthickness=0, bg=self.current_theme["bg_main"])
        self.v_scroll = ttk.Scrollbar(master, orient="vertical", command=self.main_canvas.yview)
        self.main_canvas.configure(yscrollcommand=self.v_scroll.set)
        self.v_scroll.pack(side="right", fill="y")
        self.main_canvas.pack(side="left", fill="both", expand=True)

        self.container = ttk.Frame(self.main_canvas, padding=10, style="TFrame")
        self.container_id = self.main_canvas.create_window((0, 0), window=self.container, anchor="nw")

        self.container.bind("<Configure>", lambda e: self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all")))
        self.main_canvas.bind("<Configure>", self._on_main_canvas_resize)

        # Navbar and contents
        self.create_navbar()
        self.create_content_frames()
        self.setup_keyboard_shortcuts()

        # Start on Generator tab
        self.show_frame(GeneratorFrame)
        self.generate_and_display()  # initial password

    def _on_main_canvas_resize(self, event):
        # ensure the inner frame width matches canvas width
        self.main_canvas.itemconfig(self.container_id, width=event.width)

    # Persistence Methods
    def _load_history(self):
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r') as f:
                    history = json.load(f)
                    return history[:MAX_HISTORY]
            except (json.JSONDecodeError, IOError):
                return []
        return []

    def save_history(self):
        try:
            with open(HISTORY_FILE, 'w') as f:
                json.dump(self.password_history, f, indent=4)
        except IOError as e:
            print(f"Error saving history: {e}")

    # UI / Theme / Navigation
    def _apply_theme(self, theme_data):
        self.current_theme = theme_data
        self.master.tk_setPalette(background=theme_data["bg_main"], foreground=theme_data["fg_text"])
        style = ttk.Style()
        style.theme_use('clam')

        # General Styles
        style.configure("TFrame", background=theme_data["bg_main"])
        style.configure("TLabel", background=theme_data["bg_main"], foreground=theme_data["fg_text"], font=DEFAULT_FONT)
        style.configure("TCheckbutton", 
                        background=theme_data["bg_main"], 
                        foreground=theme_data["fg_text"], 
                        font=DEFAULT_FONT,
                        indicatorrelief="flat") # Cleaner look for checkboxes

        # NEW: Card Style for output display and history items. Uses 'solid' relief for visible border.
        style.configure("Card.TFrame", 
                        background=theme_data["bg_secondary"],
                        bordercolor=theme_data["border_color"],
                        borderwidth=1,
                        relief='solid')

        # Base Button Style
        style.configure("TButton",
                        font=('Inter', 12, 'bold'),
                        background=theme_data["trough"], # Default button is dark
                        foreground=theme_data["fg_text"],
                        relief="flat",
                        padding=[16, 8],
                        borderwidth=0,
                        focuscolor=theme_data["primary"])
        style.map("TButton", 
                  background=[('active', theme_data["border_color"])])

        # Primary Action Button Style
        style.configure("Primary.TButton",
                        font=('Inter', 12, 'bold'),
                        background=theme_data["primary"],
                        foreground=theme_data["bg_secondary"]) # Dark text on bright button
        style.map("Primary.TButton", 
                  background=[('active', theme_data["primary"])]) # Keep color strong on active
        
        # Action Button Styles
        style.configure("Success.TButton", background=theme_data["success"], foreground=theme_data["bg_secondary"])
        style.configure("Danger.TButton", background=theme_data["danger"], foreground=theme_data["bg_secondary"])

        # Navbar Styles (buttons in the header)
        style.configure("Navbar.TButton",
                        font=('Inter', 13, 'bold'),
                        background=theme_data["bg_main"],
                        foreground=theme_data["fg_text"],
                        relief="flat",
                        padding=[14, 8])
        style.map("Navbar.TButton",
                  background=[('active', theme_data["border_color"]), ('!disabled', theme_data["bg_main"])],
                  foreground=[('active', theme_data["primary"]), ('!disabled', theme_data["fg_text"])])

        style.configure("NavbarActive.TButton",
                        font=('Inter', 13, 'bold'),
                        background=theme_data["primary"],
                        foreground=theme_data["bg_main"],
                        relief="flat",
                        padding=[14, 8])
        
        # Progress Bar Styles
        style.configure("TProgressbar", troughcolor=theme_data["trough"], bordercolor=theme_data["trough"], thickness=14)

        # Define styles for each strength level
        style.configure("Weak.Horizontal.TProgressbar", background=theme_data["danger"])
        style.configure("Medium.Horizontal.TProgressbar", background=theme_data["medium"])
        style.configure("Good.Horizontal.TProgressbar", background=theme_data["primary"])
        style.configure("Strong.Horizontal.TProgressbar", background=theme_data["success"])

        self.update_widget_colors()

    def update_widget_colors(self):
        theme = self.current_theme
        color_map = {
            'bg': theme["bg_secondary"],
            'fg': theme["fg_text"],
            'readonlybackground': theme["bg_secondary"],
            'insertbackground': theme["fg_text"]
        }
        
        # Update colors for hardcoded Entry/Text widgets
        for frame in getattr(self, "frames", {}).values():
            try:
                frame.password_display.config(**color_map)
            except Exception:
                pass
            
            try:
                frame.typed_pass_field.config(**color_map)
            except Exception:
                pass
                
            try:
                frame.suggestions_text.config(bg=theme["bg_secondary"], fg=theme["fg_text"], highlightbackground=theme["trough"])
            except Exception:
                pass
            
            # Update history frame text entry colors
            if isinstance(frame, HistoryFrame):
                 frame.history_canvas.config(bg=theme["bg_main"])
                 frame.update_history_display() # force a redraw with new colors

    def toggle_theme(self):
        self.is_dark_theme_var.set(not self.is_dark_theme_var.get())
        theme_name = "dark" if self.is_dark_theme_var.get() else "light"
        self._apply_theme(THEMES[theme_name])
        # Re-initialize frames to pick up changes in widget creation
        self.create_content_frames()
        # Restore the currently visible frame
        for F, frame in self.frames.items():
            if frame.winfo_ismapped():
                self.show_frame(F)
                break
        self.master.update()


    def create_navbar(self):
        self.navbar = ttk.Frame(self.container, style="TFrame")
        self.navbar.pack(side="top", fill="x", pady=(4, 8))

        ttk.Label(self.navbar, text="SecureGen", font=('Inter', 24, 'bold'), foreground=self.current_theme["primary"]).pack(side="left", padx=15)

        self.nav_buttons = {}
        nav_configs = [
            ("🔐 Generator", GeneratorFrame),
            ("📋 History", HistoryFrame),
            ("🧠 Checker", StrengthCheckerFrame)
        ]
        for text, frame_class in nav_configs:
            btn = ttk.Button(self.navbar, text=text,
                             command=lambda fc=frame_class: self.show_frame(fc),
                             style="Navbar.TButton")
            btn.pack(side="left", padx=6)
            self.nav_buttons[frame_class] = btn

        # Fullscreen toggle
        self._is_fullscreen = False
        self.fullscreen_btn = ttk.Button(self.navbar, text="⛶ Fullscreen", command=self._toggle_fullscreen, style="TButton")
        self.fullscreen_btn.pack(side="right", padx=8)

        theme_btn = ttk.Button(self.navbar, text="🎨 Theme", command=self.toggle_theme, style="TButton")
        theme_btn.pack(side="right", padx=6)

    def _toggle_fullscreen(self):
        self._is_fullscreen = not self._is_fullscreen
        self.master.attributes("-fullscreen", self._is_fullscreen)
        self.fullscreen_btn.config(text="⬜ Exit" if self._is_fullscreen else "⛶ Fullscreen")

    def create_content_frames(self):
        if hasattr(self, 'content_container') and self.content_container.winfo_exists():
            self.content_container.destroy()

        self.content_container = ttk.Frame(self.container, style="TFrame", padding="8")
        self.content_container.pack(side="top", fill="both", expand=True)

        for F in (GeneratorFrame, HistoryFrame, StrengthCheckerFrame):
            # Pass controller for theme data
            frame = F(self.content_container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
        for f_class, btn in self.nav_buttons.items():
            if f_class == cont:
                btn.config(style="NavbarActive.TButton")
                if f_class == HistoryFrame:
                    # History frame must refresh its display on show
                    frame.update_history_display() 
            else:
                btn.config(style="Navbar.TButton")

    # Core Functionality

    def check_breach_status(self, password, callback):
        """
        Securely checks if a password has appeared in a known data breach using
        the Have I Been Pwned Pwned Passwords API.
        
        Uses local in-memory caching to reduce API requests.
        """
        # 1. Local Hashing
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        count = 0

        # 2. Check Cache
        if prefix in self.breach_cache:
            response_data = self.breach_cache[prefix]
        else:
            # 3. Request HIBP API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            try:
                # Use a minimal request (user-agent is required by some networks/proxies)
                req = Request(url, headers={'User-Agent': 'SecureGenTkinterApp'})
                with urlopen(req, timeout=5) as response:
                    if response.getcode() == 200:
                        response_data = response.read().decode('utf-8')
                        self.breach_cache[prefix] = response_data
                    else:
                        response_data = None
            except URLError as e:
                print(f"Breach check connection error: {e}")
                callback(None) # Indicate connection error
                return
            except Exception as e:
                print(f"Breach check general error: {e}")
                callback(None)
                return

        # 4. Compare Suffixes
        if response_data:
            lines = response_data.split('\r\n')
            for line in lines:
                if not line:
                    continue
                h, c = line.split(':')
                if h == suffix:
                    count = int(c)
                    break
        
        callback(count)


    def generate_and_display(self, event=None):
        length = self.length_var.get()
        
        # Pass the new ambiguous character setting to the char pool function
        char_pool, char_sets_count = get_char_pool(
            self.lowercase_var.get(), 
            self.uppercase_var.get(), 
            self.digits_var.get(), 
            self.symbols_var.get(),
            avoid_ambiguous=self.avoid_ambiguous_var.get() # PASSED HERE
        )

        generator_frame = self.frames.get(GeneratorFrame)

        if char_sets_count == 0:
            if generator_frame:
                generator_frame.update_display("ERROR: Select at least one set.", 0.0)
                generator_frame.update_strength_bar(0, "Weak")
                generator_frame.handle_breach_result(0) # Reset breach status
            return

        char_sets_for_guarantee = []
        if self.lowercase_var.get():
            char_sets_for_guarantee.append(LOWERCASE)
        if self.uppercase_var.get():
            char_sets_for_guarantee.append(UPPERCASE)
        if self.digits_var.get():
            char_sets_for_guarantee.append(DIGITS)
        if self.symbols_var.get():
            char_sets_for_guarantee.append(ADVANCED_SYMBOLS)

        password = generate_secure_password(length, char_pool, char_sets_for_guarantee, prevent_repetition=False)

        score, strength_text, entropy = evaluate_strength_score(len(password), len(char_pool))

        if generator_frame:
            generator_frame.update_display(password, entropy)
            generator_frame.strength_bar.config(style=f"{strength_text}.Horizontal.TProgressbar")
            self._animate_strength_bar(generator_frame.strength_bar, score, strength_text)
            
            # NEW: Trigger Breach Check
            theme = self.current_theme
            generator_frame.breach_status_label.config(text="⏳ Checking breach database...", foreground=theme["medium"])
            # Run the check in the main loop to avoid threading complexity, but show loading instantly
            self.master.after(100, lambda: self.check_breach_status(password, generator_frame.handle_breach_result))

        self._add_to_history(password)

    def _animate_strength_bar(self, widget, target_score, strength_text):
        current = int(widget['value']) if widget['value'] else 0
        step = 1 if target_score > current else -1

        def anim():
            nonlocal current
            if current == target_score:
                frame = self.frames.get(GeneratorFrame)
                if frame:
                    frame.update_strength_bar(target_score, strength_text)
                return
            
            # Simple linear step to target
            current = current + step
            if (step > 0 and current > target_score) or (step < 0 and current < target_score):
                current = target_score

            widget.config(value=current)
            self.master.after(6, anim)

        anim()

    def _add_to_history(self, password):
        entry = {"password": password, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
        self.password_history.insert(0, entry)
        if len(self.password_history) > MAX_HISTORY:
            self.password_history = self.password_history[:MAX_HISTORY]
        self.save_history()

    def copy_to_clipboard(self, password=None, event=None):
        generator_frame = self.frames.get(GeneratorFrame)
        
        # Check if the user is copying from the generator frame or history frame
        if password is None and generator_frame:
            password = generator_frame.password_display.get()
            is_from_generator = True
        else:
            is_from_generator = False

        if not password or "ERROR" in password:
            return
        
        # Use platform-independent clipboard access
        try:
            self.master.clipboard_clear()
            self.master.clipboard_append(password)
            if is_from_generator and generator_frame:
                generator_frame.show_feedback("Password Copied!", "success")
        except Exception as e:
            if is_from_generator and generator_frame:
                generator_frame.show_feedback(f"Clipboard Error: {e}", "danger")

    def save_password_file(self):
        generator_frame = self.frames.get(GeneratorFrame)
        if not generator_frame:
            return
        password = generator_frame.password_display.get()
        if not password or "ERROR" in password:
            generator_frame.show_feedback("No password to save.", "danger")
            return
            
        site = self.site_var.get()
        username = self.username_var.get()

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")],
            title="Save Password Entry"
        )
        if not file_path:
            return
        try:
            with open(file_path, 'w') as f:
                if file_path.lower().endswith('.csv'):
                    QUOTE = chr(34)
                    DOUBLED_QUOTE = QUOTE * 2
                    f.write("Timestamp,Website/Site,Username,Password\n")
                    f.write(f'{time.strftime("%Y-%m-%d %H:%M:%S")},{QUOTE}{site.replace(QUOTE, DOUBLED_QUOTE)}{QUOTE},{QUOTE}{username.replace(QUOTE, DOUBLED_QUOTE)}{QUOTE},{QUOTE}{password.replace(QUOTE, DOUBLED_QUOTE)}{QUOTE}\n')
                    msg = "Entry exported to CSV!"
                else:
                    f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Site: {site if site else 'N/A'}\n")
                    f.write(f"Username: {username if username else 'N/A'}\n")
                    f.write(f"Password: {password}\n")
                    msg = "Password saved to TXT!"
            generator_frame.show_feedback(msg, "success")
        except Exception as e:
            generator_frame.show_feedback(f"Save Error: {e}", "danger")

    def setup_keyboard_shortcuts(self):
        self.master.bind('<Control-g>', self.generate_and_display)
        self.master.bind('<Control-c>', self.copy_to_clipboard)
        self.master.bind('<Control-q>', lambda event: self.master.quit())


# --- CLI Functionality (Unchanged for logic) ---

def run_cli():
    parser = argparse.ArgumentParser(
        description="Generate a cryptographically secure password from the command line."
    )

    parser.add_argument(
        '--length',
        type=int,
        required=True,
        help="Desired password length (8-32 recommended)."
    )

    parser.add_argument(
        '--sets',
        type=str,
        required=True,
        help="Character sets to use. Options: 'l' (lower), 'u' (upper), 'd' (digits), 's' (symbols). E.g., 'luds'."
    )

    # Added CLI argument for avoiding ambiguous characters
    parser.add_argument(
        '--no-ambiguous',
        action='store_true',
        help="Exclude ambiguous characters (0, O, l, 1, I, etc.) for easier manual entry."
    )


    try:
        # Use an internal parser call to allow the script to continue if no args are passed
        if len(sys.argv) == 2 and sys.argv[1].lower() in ('--help', '-h'):
            parser.print_help()
            return
        
        args = parser.parse_args()
    except SystemExit:
        # Only exit gracefully if the user explicitly requested help. Otherwise, raise an error.
        if '--help' not in sys.argv and '-h' not in sys.argv:
            print("CLI execution failed. Check arguments or run without args for GUI.")
        return

    if not 8 <= args.length <= 32:
        print(f"Error: Length {args.length} is outside the recommended range (8-32).")
        return

    char_sets_map = {
        'l': LOWERCASE,
        'u': UPPERCASE,
        'd': DIGITS,
        's': ADVANCED_SYMBOLS
    }

    selected_sets = []
    for char_code in args.sets.lower():
        if char_code in char_sets_map:
            selected_sets.append(char_sets_map[char_code])

    if not selected_sets:
        print("Error: No valid character sets selected. Use 'l', 'u', 'd', 's'.")
        return

    # Pass the ambiguous character setting
    char_pool, _ = get_char_pool(
        'l' in args.sets.lower(), 
        'u' in args.sets.lower(),
        'd' in args.sets.lower(), 
        's' in args.sets.lower(),
        avoid_ambiguous=args.no_ambiguous
    )
    
    # Filter the list of sets used for guaranteed character inclusion to ensure they only contain characters in the final pool
    filtered_sets = [
        "".join(c for c in char_set if c in char_pool)
        for char_set in selected_sets
    ]

    password = generate_secure_password(args.length, char_pool, filtered_sets, prevent_repetition=False)
    entropy = calculate_entropy(len(password), len(char_pool))
    print(password)
    print(f"(Entropy: {entropy:.2f} bits)")


# --- Main Execution ---

if __name__ == "__main__":
    # Check if we are running in CLI mode
    is_cli = False
    if len(sys.argv) > 1:
        # Check if any non-standard/non-help argument is present
        valid_cli_args = ['--length', '--sets', '-h', '--help', '--no-ambiguous']
        if any(arg.startswith('--') and arg.split('=')[0] in valid_cli_args for arg in sys.argv[1:]):
            is_cli = True
        elif any(arg in valid_cli_args for arg in sys.argv[1:]):
             is_cli = True # allows -h

    if is_cli and len(sys.argv) > 1 and all(arg not in ('--help', '-h') for arg in sys.argv[1:]):
        # We run the CLI parser only if explicit password generation arguments are provided
        run_cli()
    else:
        root = tk.Tk()
        try:
            # Tkinter only supports a limited set of system fonts, we keep the fallback simple.
            root.option_add('*Font', 'Arial 12')
        except Exception:
            pass
        app = PasswordGeneratorApp(root)
        root.mainloop()
