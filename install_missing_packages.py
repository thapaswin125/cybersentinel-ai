"""
Install Missing Dependencies
"""

import subprocess
import sys

def install_packages():
    packages = [
        'scikit-learn',
        'beautifulsoup4'
    ]

    print("Installing missing packages...")

    for package in packages:
        print(f"Installing {package}...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"✅ {package} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {package}: {e}")

    print("\nInstallation complete!")
    print("Now run: python complete_project_test.py")

if __name__ == "__main__":
    install_packages()
