"""
CyberSentinel AI - Quick Status Checker
Quick overview of project health
"""

import os

def quick_status_check():
    print("🛡️ CyberSentinel AI - Quick Status Check")
    print("=" * 50)

    # Check core files
    core_files = [
        'index.html', 'style.css', 'app.js',
        'ai_threat_detector.py', 'osint_collector.py', 'soar_engine.py',
        'demo.py', 'requirements.txt'
    ]

    print("\n📁 Core Files:")
    missing = []
    for file in core_files:
        if os.path.exists(file):
            print(f"✅ {file}")
        else:
            print(f"❌ {file} - MISSING")
            missing.append(file)

    # Check key dependencies
    print("\n📦 Key Dependencies:")
    key_deps = ['pandas', 'numpy', 'sklearn', 'requests', 'flask']

    for dep in key_deps:
        try:
            __import__(dep)
            print(f"✅ {dep}")
        except ImportError:
            print(f"❌ {dep} - NOT INSTALLED")

    # Overall status
    print("\n📊 Status Summary:")
    if not missing:
        print("✅ All core files present")
    else:
        print(f"❌ Missing {len(missing)} files: {missing}")

    print("\n💡 Next Steps:")
    print("1. Run: python complete_project_test.py  (comprehensive test)")
    print("2. Run: python demo.py  (see project in action)")
    print("3. Open: index.html  (view web dashboard)")

if __name__ == "__main__":
    quick_status_check()
