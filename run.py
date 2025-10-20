#!/usr/bin/env python3

import sys
import subprocess

def check_dependencies():
    """Check if all required dependencies are installed."""
    try:
        import PyQt5
        print("✓ PyQt5 is installed")
    except ImportError:
        print("✗ PyQt5 is not installed")
        print("\nInstalling PyQt5...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "PyQt5>=5.15.9"])
        print("✓ PyQt5 installed successfully")

    missing_deps = []
    deps = [
        'dotenv', 'requests', 'dns', 'bs4', 'cachetools',
        'whois', 'reportlab', 'sklearn', 'networkx',
        'plotly', 'schedule', 'Crypto', 'apscheduler',
        'joblib', 'cryptography', 'numpy', 'pandas',
        'lxml', 'urllib3', 'certifi', 'yaml'
    ]

    for dep in deps:
        try:
            __import__(dep)
        except ImportError:
            missing_deps.append(dep)

    if missing_deps:
        print(f"\n⚠ Missing dependencies: {', '.join(missing_deps)}")
        print("\nInstalling missing dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ All dependencies installed")
    else:
        print("✓ All dependencies are installed")

if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  Advanced Domain Reconnaissance Desktop Application")
    print("=" * 60)
    print("\nChecking dependencies...\n")

    try:
        check_dependencies()
        print("\n" + "=" * 60)
        print("Starting application...")
        print("=" * 60 + "\n")

        from desktop_app import main
        main()

    except KeyboardInterrupt:
        print("\n\nApplication terminated by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        print("\nPlease ensure all dependencies are installed:")
        print("  pip install -r requirements.txt")
        sys.exit(1)
