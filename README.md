# SecureGen | Advanced Password Generator & Security Manager

## 📋 Project Overview

**SecureGen** is a comprehensive, cryptographically secure password generation and management tool built with Python and Tkinter. It provides both a user-friendly GUI and a CLI interface for generating strong, customizable passwords with real-time strength analysis and breach detection capabilities.

---

## 🎯 Objective

Create a robust password generation system that:
- Generates cryptographically secure passwords using industry-standard algorithms
- Provides real-time strength evaluation with entropy calculations
- Detects compromised passwords against known breaches (HIBP integration)
- Offers both graphical and command-line interfaces
- Maintains local password history with persistent storage
- Implements modern, themeable UI with dark/light mode support

---

## 🔧 Steps Performed

### 1. **Core Security Implementation**
   - Implemented `secrets` module for cryptographically secure random generation
   - Created entropy calculation using Shannon entropy formula: `bits = length × log₂(pool_size)`
   - Developed character pool management with configurable charsets (lowercase, uppercase, digits, symbols)
   - Added ambiguous character filtering to prevent manual entry errors

### 2. **GUI Development**
   - Built modular Tkinter interface with three main tabs:
     - **Generator Tab**: Password creation with real-time controls
     - **History Tab**: Password history with copy/delete functionality
     - **Checker Tab**: Manual strength analysis and breach detection
   - Implemented smooth animations for progress bars and strength indicators
   - Created responsive layouts with canvas-based scrolling support

### 3. **Breach Detection System**
   - Integrated Haven I Been Pwned (HIBP) Pwned Passwords API
   - Implemented SHA-1 hashing with prefix API calls for privacy (only prefix sent to API)
   - Added in-memory caching to reduce API requests and improve performance
   - Non-blocking async pattern to prevent UI freezing during network calls

### 4. **Theme & UX Enhancements**
   - Created comprehensive dark and light theme system (GitHub-inspired dark theme)
   - Implemented color-coded strength indicators (Weak/Medium/Good/Strong)
   - Added dynamic theme toggling with full widget re-styling
   - Designed intuitive component frames with semantic visual hierarchy

### 5. **Data Persistence**
   - Built JSON-based history storage with configurable retention (`MAX_HISTORY = 10`)
   - Implemented file export functionality (CSV/TXT formats)
   - Added metadata fields for site/username association

### 6. **CLI Implementation**
   - Developed command-line interface with argparse
   - Supported character set selection flags (`l`, `u`, `d`, `s`)
   - Added entropy output and error handling
   - Maintained feature parity with GUI (including ambiguous character filtering)

### 7. **Keyboard Shortcuts**
   - `Ctrl+G`: Generate password
   - `Ctrl+C`: Copy to clipboard
   - `Ctrl+Q`: Quit application

---

## 🛠️ Tools & Technologies Used

| Component | Tool/Library | Purpose |
|-----------|--------------|---------|
| **GUI Framework** | Tkinter (ttk) | Cross-platform UI rendering |
| **Cryptography** | `secrets` module | Secure random number generation |
| **Hashing** | `hashlib` (SHA-1) | Password hashing for HIBP API |
| **API Integration** | `urllib` | HTTP requests to HIBP API |
| **CLI** | `argparse` | Command-line argument parsing |
| **Data Storage** | `json` | Password history persistence |
| **Math** | `math` module | Entropy calculations |
| **System** | `os`, `sys` | File/process handling |

**Dependencies**: Python 3.6+ (standard library only, no external packages required)

---

## 📊 Key Features

### Password Generation
- ✅ Lengths 8-32 characters
- ✅ Customizable character sets (4 types)
- ✅ Guaranteed character diversity from each selected set
- ✅ Optional ambiguous character exclusion (0, O, l, 1, I, S, 5, Z, 2, z, |, {}, [], /, ', `, ~, ., ,, ;, :)
- ✅ Cryptographically secure using `secrets.SystemRandom()`

### Strength Analysis
- ✅ Real-time entropy calculation (bits)
- ✅ Four-tier strength assessment (Weak/Medium/Good/Strong)
- ✅ Contextual suggestions for improvement
- ✅ Visual progress bars with color-coding

### Breach Detection
- ✅ Integration with Have I Been Pwned API
- ✅ Privacy-preserving k-anonymity pattern matching
- ✅ In-memory response caching
- ✅ Non-blocking async checks with user feedback

### History Management
- ✅ Persistent JSON storage
- ✅ Timestamp tracking
- ✅ One-click copy/delete
- ✅ Configurable retention limit

### UI/UX
- ✅ Dark and light themes
- ✅ Responsive design with scrolling support
- ✅ Fullscreen toggle
- ✅ Password visibility toggle
- ✅ Smooth animations and micro-interactions
- ✅ Accessibility-focused design

---

## 🚀 Usage

### GUI Mode (Default)
```bash
python securegen.py
```

### CLI Mode
```bash
# Generate 16-character password with all character sets
python securegen.py --length 16 --sets luds

# Generate 20-character password without ambiguous characters
python securegen.py --length 20 --sets luds --no-ambiguous

# Get help
python securegen.py --help
```

**CLI Options:**
- `--length`: Password length (8-32, required)
- `--sets`: Character sets to use (required)
  - `l`: lowercase letters
  - `u`: uppercase letters
  - `d`: digits (0-9)
  - `s`: symbols (!@#$%^&*...)
- `--no-ambiguous`: Exclude ambiguous characters (optional)

---

## 📁 File Structure

```
securegen/
├── password_history.json    # Persistent password history (auto-generated)
├── securegen.py             # Main application file (standalone)
└── README.md                # This file
```

---

## 🔐 Security Considerations

1. **Cryptographic Randomness**: Uses Python's `secrets` module (OS-level randomness)
2. **HIBP API Privacy**: Only sends password hash prefix (5 chars), not full hash
3. **Local Caching**: Reduces API calls; data cleared on session end
4. **No External Dependencies**: Minimizes attack surface
5. **Clipboard Clearing**: Users must manually manage clipboard security
6. **Password Visibility**: Toggle-able for user verification; defaults to masked

---

## 📈 Entropy Strength Tiers

| Entropy (bits) | Tier | Assessment |
|---|---|---|
| < 60 | Weak | ❌ Not recommended |
| 60-90 | Medium | ⚠️ Acceptable for low-security accounts |
| 90-128 | Good | ✅ Recommended for most uses |
| > 128 | Strong | 🔒 Excellent for high-security needs |

**Note**: 128 bits is the modern cryptographic security standard (NIST guidelines).

---

## 🎨 Theme Colors (Dark Mode Example)

| Element | Color | Purpose |
|---------|-------|---------|
| Background | `#0D1117` | Main dark surface |
| Primary Accent | `#58A6FF` | Interactive elements |
| Success | `#3FB950` | Positive feedback |
| Warning | `#FCD34D` | Caution indicators |
| Danger | `#F85149` | Errors/warnings |

---

## ⚙️ Configuration

Edit constants in `securegen.py`:

```python
HISTORY_FILE = "password_history.json"  # History file path
MAX_HISTORY = 10                         # Max stored entries
ADVANCED_SYMBOLS = '!@#$%^&*()_+=-...'   # Custom symbol set
AMBIGUOUS_CHARS = set('0OolI1S5Z2z...')  # Ambiguous chars to filter
```

---

## 🐛 Troubleshooting

### Password Display Not Updating
- Ensure at least one character set is selected
- Check that password length is 8-32 characters

### Breach Check Fails
- Verify internet connection (HIBP API requires connectivity)
- Check firewall/proxy settings
- HIBP API may have rate limiting; wait before retrying

### GUI Rendering Issues
- Ensure Tkinter is installed: `python -m tkinter`
- On Linux, install: `sudo apt-get install python3-tk`
- Update Python to latest patch version

### History Not Persisting
- Verify write permissions in the working directory
- Check `password_history.json` file isn't corrupted
- Delete file to reset: next generation creates a new one

---

## 📋 Outcome

**SecureGen** successfully delivers:

✅ **Production-Ready Application**: Fully functional GUI and CLI with no external dependencies  
✅ **Security Validated**: Real breach detection via HIBP with privacy-preserving architecture  
✅ **User-Centric Design**: Intuitive interface with multiple themes and accessibility features  
✅ **Comprehensive Features**: Password generation, strength analysis, history management, and export capabilities  
✅ **Educational Value**: Clean, documented code demonstrating cryptographic best practices  
✅ **Cross-Platform Compatible**: Runs on Windows, macOS, and Linux  

The application serves as both a practical security tool and a reference implementation for secure password handling.

---

