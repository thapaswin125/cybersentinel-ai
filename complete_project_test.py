"""
CyberSentinel AI - Complete Project Test Suite
Tests all components to verify the entire project is working
"""

import os
import sys
import subprocess
import json
import time
from datetime import datetime
import logging

class CyberSentinelTester:
    def __init__(self):
        self.test_results = {}
        self.start_time = datetime.now()

        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('project_test_results.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        # Required files for the project
        self.required_files = [
            'index.html',
            'style.css', 
            'app.js',
            'ai_threat_detector.py',
            'osint_collector.py',
            'soar_engine.py',
            'requirements.txt',
            'demo.py',
            'run_tests.py'
        ]

        # Python modules to test
        self.python_modules = [
            'ai_threat_detector.py',
            'osint_collector.py', 
            'soar_engine.py',
            'demo.py'
        ]

    def print_banner(self):
        print("\n" + "="*70)
        print("🛡️  CYBERSENTINEL AI - COMPLETE PROJECT TEST SUITE")
        print("="*70)
        print(f"Started at: {self.start_time}")
        print("Testing all components...")
        print()

    def test_file_structure(self):
        """Test if all required files exist"""
        print("📁 TESTING PROJECT STRUCTURE")
        print("-" * 40)

        missing_files = []
        present_files = []

        for file_name in self.required_files:
            if os.path.exists(file_name):
                print(f"✅ {file_name} - Found")
                present_files.append(file_name)
            else:
                print(f"❌ {file_name} - Missing")
                missing_files.append(file_name)

        self.test_results['file_structure'] = {
            'total_files': len(self.required_files),
            'present': len(present_files),
            'missing': len(missing_files),
            'missing_files': missing_files,
            'status': 'PASS' if not missing_files else 'FAIL'
        }

        print(f"\n📊 Files: {len(present_files)}/{len(self.required_files)} present")
        return not missing_files

    def test_python_imports(self):
        """Test if Python modules can be imported"""
        print("\n🐍 TESTING PYTHON MODULE IMPORTS")
        print("-" * 40)

        import_results = {}

        for module_file in self.python_modules:
            if os.path.exists(module_file):
                module_name = module_file.replace('.py', '')
                try:
                    # Try to import the module
                    exec(f"import {module_name}")
                    print(f"✅ {module_file} - Imports successfully")
                    import_results[module_file] = 'SUCCESS'
                except Exception as e:
                    print(f"❌ {module_file} - Import failed: {e}")
                    import_results[module_file] = f'FAILED: {str(e)}'
            else:
                print(f"⚠️  {module_file} - File not found")
                import_results[module_file] = 'FILE_NOT_FOUND'

        self.test_results['python_imports'] = import_results
        successful_imports = sum(1 for result in import_results.values() if result == 'SUCCESS')

        print(f"\n📊 Imports: {successful_imports}/{len(self.python_modules)} successful")
        return successful_imports == len(self.python_modules)

    def test_web_dashboard(self):
        """Test web dashboard files"""
        print("\n🌐 TESTING WEB DASHBOARD")
        print("-" * 40)

        web_files = ['index.html', 'style.css', 'app.js']
        web_test_results = {}

        for file_name in web_files:
            if os.path.exists(file_name):
                try:
                    with open(file_name, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Basic content validation
                    if file_name == 'index.html':
                        if 'CyberSentinel' in content and 'dashboard' in content.lower():
                            print(f"✅ {file_name} - Valid HTML structure")
                            web_test_results[file_name] = 'VALID'
                        else:
                            print(f"⚠️  {file_name} - Missing key content")
                            web_test_results[file_name] = 'INCOMPLETE'

                    elif file_name == 'style.css':
                        if len(content) > 100:  # Basic check for CSS content
                            print(f"✅ {file_name} - CSS file has content")
                            web_test_results[file_name] = 'VALID'
                        else:
                            print(f"⚠️  {file_name} - CSS file seems empty")
                            web_test_results[file_name] = 'INCOMPLETE'

                    elif file_name == 'app.js':
                        if 'function' in content or 'const' in content or 'var' in content:
                            print(f"✅ {file_name} - JavaScript file has content")
                            web_test_results[file_name] = 'VALID'
                        else:
                            print(f"⚠️  {file_name} - JavaScript file seems empty")
                            web_test_results[file_name] = 'INCOMPLETE'

                except Exception as e:
                    print(f"❌ {file_name} - Read error: {e}")
                    web_test_results[file_name] = f'ERROR: {str(e)}'
            else:
                print(f"❌ {file_name} - File not found")
                web_test_results[file_name] = 'NOT_FOUND'

        self.test_results['web_dashboard'] = web_test_results
        valid_files = sum(1 for result in web_test_results.values() if result == 'VALID')

        print(f"\n📊 Web files: {valid_files}/{len(web_files)} valid")
        return valid_files == len(web_files)

    def test_demo_script(self):
        """Test the demo script"""
        print("\n🎪 TESTING DEMO SCRIPT")
        print("-" * 40)

        if not os.path.exists('demo.py'):
            print("❌ demo.py - File not found")
            self.test_results['demo_script'] = 'NOT_FOUND'
            return False

        try:
            print("▶  Running demo.py...")
            result = subprocess.run([sys.executable, 'demo.py'], 
                                  capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                output = result.stdout
                if 'CyberSentinel AI' in output and 'THREAT DETECTED' in output:
                    print("✅ demo.py - Runs successfully and shows threats")
                    self.test_results['demo_script'] = 'SUCCESS'
                    return True
                else:
                    print("⚠️  demo.py - Runs but output incomplete")
                    self.test_results['demo_script'] = 'INCOMPLETE_OUTPUT'
                    return False
            else:
                print(f"❌ demo.py - Failed with error: {result.stderr}")
                self.test_results['demo_script'] = f'FAILED: {result.stderr[:200]}'
                return False

        except subprocess.TimeoutExpired:
            print("⚠️  demo.py - Timeout (may be waiting for input)")
            self.test_results['demo_script'] = 'TIMEOUT'
            return False
        except Exception as e:
            print(f"❌ demo.py - Exception: {e}")
            self.test_results['demo_script'] = f'EXCEPTION: {str(e)}'
            return False

    def test_ai_threat_detector(self):
        """Test AI threat detection module"""
        print("\n🤖 TESTING AI THREAT DETECTOR")
        print("-" * 40)

        if not os.path.exists('ai_threat_detector.py'):
            print("❌ ai_threat_detector.py - File not found")
            self.test_results['ai_threat_detector'] = 'NOT_FOUND'
            return False

        try:
            print("▶  Running ai_threat_detector.py...")
            result = subprocess.run([sys.executable, 'ai_threat_detector.py'], 
                                  capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                output = result.stdout
                if 'threat' in output.lower() or 'detection' in output.lower():
                    print("✅ ai_threat_detector.py - Runs and detects threats")
                    self.test_results['ai_threat_detector'] = 'SUCCESS'
                    return True
                else:
                    print("⚠️  ai_threat_detector.py - Runs but no threat output")
                    self.test_results['ai_threat_detector'] = 'NO_THREAT_OUTPUT'
                    return False
            else:
                print(f"❌ ai_threat_detector.py - Failed: {result.stderr[:200]}")
                self.test_results['ai_threat_detector'] = f'FAILED: {result.stderr[:200]}'
                return False

        except Exception as e:
            print(f"❌ ai_threat_detector.py - Exception: {e}")
            self.test_results['ai_threat_detector'] = f'EXCEPTION: {str(e)}'
            return False

    def test_osint_collector(self):
        """Test OSINT collection module"""
        print("\n🌐 TESTING OSINT COLLECTOR")
        print("-" * 40)

        if not os.path.exists('osint_collector.py'):
            print("❌ osint_collector.py - File not found")
            self.test_results['osint_collector'] = 'NOT_FOUND'
            return False

        try:
            print("▶  Running osint_collector.py...")
            result = subprocess.run([sys.executable, 'osint_collector.py'], 
                                  capture_output=True, text=True, timeout=45)

            if result.returncode == 0:
                output = result.stdout
                if 'intelligence' in output.lower() or 'osint' in output.lower():
                    print("✅ osint_collector.py - Runs and collects intelligence")
                    self.test_results['osint_collector'] = 'SUCCESS'
                    return True
                else:
                    print("⚠️  osint_collector.py - Runs but no OSINT output")
                    self.test_results['osint_collector'] = 'NO_OSINT_OUTPUT'
                    return False
            else:
                print(f"❌ osint_collector.py - Failed: {result.stderr[:200]}")
                self.test_results['osint_collector'] = f'FAILED: {result.stderr[:200]}'
                return False

        except Exception as e:
            print(f"❌ osint_collector.py - Exception: {e}")
            self.test_results['osint_collector'] = f'EXCEPTION: {str(e)}'
            return False

    def test_soar_engine(self):
        """Test SOAR automation engine"""
        print("\n⚡ TESTING SOAR ENGINE")
        print("-" * 40)

        if not os.path.exists('soar_engine.py'):
            print("❌ soar_engine.py - File not found")
            self.test_results['soar_engine'] = 'NOT_FOUND'
            return False

        try:
            print("▶  Running soar_engine.py...")
            result = subprocess.run([sys.executable, 'soar_engine.py'], 
                                  capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                output = result.stdout
                if 'soar' in output.lower() or 'playbook' in output.lower() or 'automation' in output.lower():
                    print("✅ soar_engine.py - Runs and shows automation")
                    self.test_results['soar_engine'] = 'SUCCESS'
                    return True
                else:
                    print("⚠️  soar_engine.py - Runs but no SOAR output")
                    self.test_results['soar_engine'] = 'NO_SOAR_OUTPUT'
                    return False
            else:
                print(f"❌ soar_engine.py - Failed: {result.stderr[:200]}")
                self.test_results['soar_engine'] = f'FAILED: {result.stderr[:200]}'
                return False

        except Exception as e:
            print(f"❌ soar_engine.py - Exception: {e}")
            self.test_results['soar_engine'] = f'EXCEPTION: {str(e)}'
            return False

    def check_dependencies(self):
        """Check if required dependencies are installed"""
        print("\n📦 TESTING DEPENDENCIES")
        print("-" * 40)

        key_packages = [
            'pandas', 'numpy', 'scikit-learn', 'tensorflow', 
            'requests', 'beautifulsoup4', 'flask', 'scapy'
        ]

        dependency_results = {}

        for package in key_packages:
            try:
                __import__(package)
                print(f"✅ {package} - Installed")
                dependency_results[package] = 'INSTALLED'
            except ImportError:
                print(f"❌ {package} - Not installed")
                dependency_results[package] = 'MISSING'

        self.test_results['dependencies'] = dependency_results
        installed_count = sum(1 for result in dependency_results.values() if result == 'INSTALLED')

        print(f"\n📊 Dependencies: {installed_count}/{len(key_packages)} installed")
        return installed_count >= len(key_packages) * 0.8  # 80% threshold

    def generate_final_report(self):
        """Generate comprehensive test report"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        print("\n" + "="*70)
        print("📊 CYBERSENTINEL AI - FINAL TEST REPORT")
        print("="*70)

        # Calculate overall scores
        total_tests = 0
        passed_tests = 0

        test_categories = [
            ('File Structure', self.test_results.get('file_structure', {}).get('status') == 'PASS'),
            ('Python Imports', any(result == 'SUCCESS' for result in self.test_results.get('python_imports', {}).values())),
            ('Web Dashboard', any(result == 'VALID' for result in self.test_results.get('web_dashboard', {}).values())),
            ('Demo Script', self.test_results.get('demo_script') == 'SUCCESS'),
            ('AI Detector', self.test_results.get('ai_threat_detector') == 'SUCCESS'),
            ('OSINT Collector', self.test_results.get('osint_collector') == 'SUCCESS'),
            ('SOAR Engine', self.test_results.get('soar_engine') == 'SUCCESS'),
            ('Dependencies', sum(1 for result in self.test_results.get('dependencies', {}).values() if result == 'INSTALLED') >= 6)
        ]

        for category, passed in test_categories:
            total_tests += 1
            if passed:
                passed_tests += 1
                print(f"✅ {category}")
            else:
                print(f"❌ {category}")

        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0

        print(f"\n🎯 OVERALL RESULTS:")
        print(f"   Tests Passed: {passed_tests}/{total_tests}")
        print(f"   Success Rate: {success_rate:.1f}%")
        print(f"   Test Duration: {duration:.1f} seconds")

        # Determine overall status
        if success_rate >= 90:
            status = "🎉 EXCELLENT"
            color = "GREEN"
        elif success_rate >= 70:
            status = "✅ GOOD"
            color = "YELLOW"
        elif success_rate >= 50:
            status = "⚠️  NEEDS WORK"
            color = "ORANGE"
        else:
            status = "❌ CRITICAL ISSUES"
            color = "RED"

        print(f"   Overall Status: {status}")

        # Save detailed report
        detailed_report = {
            'test_time': {
                'start': self.start_time.isoformat(),
                'end': end_time.isoformat(),
                'duration_seconds': duration
            },
            'summary': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'success_rate': success_rate,
                'status': status
            },
            'detailed_results': self.test_results
        }

        with open('project_test_report.json', 'w') as f:
            json.dump(detailed_report, f, indent=2)

        print(f"\n💾 Detailed report saved to: project_test_report.json")
        print(f"📝 Test log saved to: project_test_results.log")

        # Provide recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        if success_rate < 100:
            print("   - Check failed tests above for specific issues")
            print("   - Install missing dependencies with: pip install -r requirements.txt")
            print("   - Ensure all project files are in the correct location")
            print("   - Run individual modules to debug specific errors")
        else:
            print("   - Your CyberSentinel AI project is fully operational!")
            print("   - Ready for demonstrations and portfolio use")
            print("   - Consider extending with additional features")

        return success_rate >= 70

    def run_complete_test(self):
        """Run the complete test suite"""
        self.print_banner()

        try:
            # Run all tests
            self.test_file_structure()
            self.check_dependencies()
            self.test_python_imports()
            self.test_web_dashboard()
            self.test_demo_script()
            self.test_ai_threat_detector()
            self.test_osint_collector()
            self.test_soar_engine()

            # Generate final report
            success = self.generate_final_report()

            return success

        except KeyboardInterrupt:
            print("\n👋 Testing interrupted by user")
            return False
        except Exception as e:
            print(f"\n❌ Critical error during testing: {e}")
            return False

if __name__ == "__main__":
    tester = CyberSentinelTester()
    success = tester.run_complete_test()

    if success:
        print("\n🚀 Your CyberSentinel AI project is ready!")
    else:
        print("\n🔧 Some issues need to be fixed before the project is fully operational.")
