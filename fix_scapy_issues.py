"""
Replace Scapy Dependencies - Quick Fix
"""

import os
import shutil

def fix_scapy_issues():
    """Replace problematic Scapy files with working versions"""

    print("🛠️ Fixing Scapy import issues...")

    # Backup original if exists
    if os.path.exists('network_monitor.py'):
        print("📁 Backing up original network_monitor.py")
        shutil.copy('network_monitor.py', 'network_monitor_backup.py')

    # Replace with working version
    if os.path.exists('network_monitor_working.py'):
        print("🔄 Replacing with working version...")
        shutil.copy('network_monitor_working.py', 'network_monitor.py')
        print("✅ network_monitor.py updated successfully!")

    print("\n🚀 Test the fix:")
    print("   python network_monitor.py")
    print("\n📊 Run complete project test:")
    print("   python complete_project_test.py")

if __name__ == "__main__":
    fix_scapy_issues()
