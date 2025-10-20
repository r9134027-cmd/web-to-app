# Installation Guide

## Quick Start

### Method 1: Using the Launcher (Recommended)

Simply run:
```bash
python run.py
```

The launcher will automatically:
- Check for required dependencies
- Install missing packages
- Start the desktop application

### Method 2: Manual Installation

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Run the application:**
```bash
python desktop_app.py
```

## System Requirements

- **Python**: 3.8 or higher
- **Operating System**: Windows, macOS, or Linux
- **RAM**: Minimum 2GB (4GB recommended)
- **Internet**: Required for domain scanning

## Dependencies

The application will automatically install:
- PyQt5 (Desktop GUI framework)
- scikit-learn (Machine learning)
- networkx (Graph analysis)
- reportlab (PDF generation)
- requests (HTTP requests)
- And other required packages

## Optional API Keys

For enhanced functionality, you can add API keys to the `.env` file:

```env
VITE_VIRUSTOTAL_API_KEY=your_key_here
VITE_WHOISXMLAPI_KEY=your_key_here
VITE_GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
```

## Troubleshooting

### PyQt5 Installation Issues

**Windows:**
```bash
pip install PyQt5 --upgrade
```

**macOS:**
```bash
pip3 install PyQt5 --upgrade
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install python3-pyqt5
pip install PyQt5 --upgrade
```

### Import Errors

If you encounter import errors, reinstall all dependencies:
```bash
pip install -r requirements.txt --force-reinstall
```

### Permission Issues

**macOS/Linux:**
```bash
chmod +x run.py
python3 run.py
```

## First Run

1. Launch the application
2. Enter a domain name (e.g., google.com)
3. Click "Start Scan"
4. View results in different tabs
5. Export as PDF or JSON

## Support

If you encounter any issues:
1. Check that Python 3.8+ is installed: `python --version`
2. Verify all dependencies: `pip list`
3. Check the error messages in the application
4. Ensure you have internet connectivity

---

**Ready to scan? Run `python run.py` to get started!**
