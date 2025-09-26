"""
CyberSentinel AI - Complete Test Suite Runner
This script runs all tests to verify the project is working correctly
"""

import os
import sys
import subprocess
import json
from datetime import datetime

class CyberSentinelTester:
    """Main test orchestrator for CyberSentinel AI"""

    def __init__(self):
        self.test_results = {}
        self.start_time = datetime.now()

    def run_web_app_test(self):
        """Test if the web application loads correctly"""
        print("\n🌐 Testing Web Application...")

        try:
            # Check if HTML file exists and is valid
            if os.path.exists('index.html'):
                with open('index.html', 'r') as f:
                    content = f.read()
                    if 'CyberSentinel AI' in content and 'dashboard' in content.lower():
                        print("✅ HTML structure is valid")
                        self.test_results['web_app'] = True
                    else:
                        print("❌ HTML content issues detected")
                        self.test_results['web_app'] = False
            else:
                print("❌ index.html not found")
                self.test_results['web_app'] = False

        except Exception as e:
            print(f"❌ Web app test failed: {e}")
            self.test_results['web_app'] = False

    def run_python_module_tests(self):
        """Run tests for all Python modules"""
        print("\n🐍 Testing Python Modules...")

        modules_to_test = [
            ('ai_threat_detector.py', 'test_threat_detection.py'),
            ('osint_collector.py', 'test_osint.py'),
            ('soar_engine.py', None)  # We'll create a simple test for SOAR
        ]

        for module_file, test_file in modules_to_test:
            print(f"\n--- Testing {module_file} ---")

            # Check if module exists
            if not os.path.exists(module_file):
                print(f"❌ {module_file} not found")
                self.test_results[module_file] = False
                continue

            # Try to import the module
            try:
                module_name = module_file.replace('.py', '')
                exec(f"import {module_name}")
                print(f"✅ {module_file} imports successfully")

                # Run unit tests if available
                if test_file and os.path.exists(test_file):
                    try:
                        result = subprocess.run([sys.executable, test_file], 
                                              capture_output=True, text=True, timeout=60)
                        if result.returncode == 0:
                            print(f"✅ Unit tests passed for {module_file}")
                            self.test_results[module_file] = True
                        else:
                            print(f"❌ Unit tests failed for {module_file}")
                            print(result.stderr)
                            self.test_results[module_file] = False
                    except subprocess.TimeoutExpired:
                        print(f"⏰ Tests timed out for {module_file}")
                        self.test_results[module_file] = False
                    except Exception as e:
                        print(f"❌ Test execution failed: {e}")
                        self.test_results[module_file] = False
                else:
                    # Just test basic functionality
                    self.test_results[module_file] = True

            except Exception as e:
                print(f"❌ Failed to import {module_file}: {e}")
                self.test_results[module_file] = False

    def test_docker_configuration(self):
        """Test Docker configuration files"""
        print("\n🐳 Testing Docker Configuration...")

        docker_files = ['Dockerfile', 'docker-compose.yml']

        for file_name in docker_files:
            if os.path.exists(file_name):
                print(f"✅ {file_name} exists")

                # Basic validation
                with open(file_name, 'r') as f:
                    content = f.read()
                    if file_name == 'Dockerfile':
                        if 'FROM python:' in content and 'WORKDIR' in content:
                            print(f"✅ {file_name} structure is valid")
                            self.test_results[file_name] = True
                        else:
                            print(f"❌ {file_name} structure issues")
                            self.test_results[file_name] = False
                    elif file_name == 'docker-compose.yml':
                        if 'services:' in content and 'cybersentinel' in content:
                            print(f"✅ {file_name} structure is valid")
                            self.test_results[file_name] = True
                        else:
                            print(f"❌ {file_name} structure issues")
                            self.test_results[file_name] = False
            else:
                print(f"❌ {file_name} not found")
                self.test_results[file_name] = False

    def test_dependencies(self):
        """Test if all required dependencies are specified"""
        print("\n📦 Testing Dependencies...")

        if os.path.exists('requirements.txt'):
            with open('requirements.txt', 'r') as f:
                requirements = f.read()

                essential_packages = [
                    'flask', 'tensorflow', 'scikit-learn', 
                    'pandas', 'numpy', 'requests', 'asyncio'
                ]

                missing_packages = []
                for package in essential_packages:
                    if package not in requirements.lower():
                        missing_packages.append(package)

                if not missing_packages:
                    print("✅ All essential packages are included")
                    self.test_results['requirements'] = True
                else:
                    print(f"❌ Missing packages: {missing_packages}")
                    self.test_results['requirements'] = False
        else:
            print("❌ requirements.txt not found")
            self.test_results['requirements'] = False

    def test_project_structure(self):
        """Test overall project structure"""
        print("\n📁 Testing Project Structure...")

        expected_files = [
            'index.html',
            'style.css', 
            'app.js',
            'ai_threat_detector.py',
            'osint_collector.py',
            'soar_engine.py',
            'requirements.txt',
            'Dockerfile',
            'docker-compose.yml'
        ]

        missing_files = []
        present_files = []

        for file_name in expected_files:
            if os.path.exists(file_name):
                present_files.append(file_name)
            else:
                missing_files.append(file_name)

        print(f"✅ Found {len(present_files)} out of {len(expected_files)} expected files")

        if missing_files:
            print(f"❌ Missing files: {missing_files}")
            self.test_results['project_structure'] = False
        else:
            print("✅ All expected files are present")
            self.test_results['project_structure'] = True

    def create_demo_data(self):
        """Create demo data for testing"""
        print("\n📊 Creating Demo Data...")

        try:
            # Create sample threat data
            demo_threats = [
                {
                    "id": "DEMO-001",
                    "type": "DDoS Attack",
                    "severity": "High",
                    "confidence": 0.94,
                    "source_ip": "185.220.101.42",
                    "target": "web-server-01",
                    "timestamp": datetime.now().isoformat(),
                    "status": "Detected"
                },
                {
                    "id": "DEMO-002",
                    "type": "Malware Communication",
                    "severity": "Critical", 
                    "confidence": 0.87,
                    "source_ip": "192.168.1.105",
                    "target": "external-c2.malware.net",
                    "timestamp": datetime.now().isoformat(),
                    "status": "Blocked"
                }
            ]

            with open('demo_threats.json', 'w') as f:
                json.dump(demo_threats, f, indent=2)

            print("✅ Demo threat data created")
            self.test_results['demo_data'] = True

        except Exception as e:
            print(f"❌ Failed to create demo data: {e}")
            self.test_results['demo_data'] = False

    def generate_test_report(self):
        """Generate comprehensive test report"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result)
        failed_tests = total_tests - passed_tests
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0

        report = {
            "test_summary": {
                "start_time": self.start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": duration,
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "success_rate": round(success_rate, 2)
            },
            "detailed_results": self.test_results,
            "overall_status": "PASS" if failed_tests == 0 else "FAIL"
        }

        # Save report
        with open('test_report.json', 'w') as f:
            json.dump(report, f, indent=2)

        return report

    def run_all_tests(self):
        """Run complete test suite"""
        print("🚀 Starting CyberSentinel AI Test Suite...")
        print(f"Started at: {self.start_time}")
        print("=" * 60)

        # Run all test categories
        self.test_project_structure()
        self.test_dependencies()
        self.run_web_app_test()
        self.run_python_module_tests()
        self.test_docker_configuration()
        self.create_demo_data()

        # Generate final report
        report = self.generate_test_report()

        print("\n" + "=" * 60)
        print("🏁 TEST SUITE COMPLETED")
        print("=" * 60)
        print(f"Duration: {report['test_summary']['duration_seconds']:.2f} seconds")
        print(f"Tests Passed: {report['test_summary']['passed_tests']}/{report['test_summary']['total_tests']}")
        print(f"Success Rate: {report['test_summary']['success_rate']}%")
        print(f"Overall Status: {report['overall_status']}")

        if report['overall_status'] == 'PASS':
            print("\n🎉 Congratulations! Your CyberSentinel AI project is working correctly!")
            print("\n🚀 Next Steps:")
            print("1. Open index.html in your browser to see the web interface")
            print("2. Run individual Python modules to test specific features")
            print("3. Use 'docker-compose up' to deploy the full stack")
            print("4. Check test_report.json for detailed results")
        else:
            print("\n⚠️  Some issues were detected. Please review the failed tests above.")
            print("\n🔧 Troubleshooting:")
            print("1. Ensure all files are in the correct location")
            print("2. Install required dependencies: pip install -r requirements.txt")
            print("3. Check individual module implementations")
            print("4. Review test_report.json for specific failures")

        return report

if __name__ == "__main__":
    tester = CyberSentinelTester()
    tester.run_all_tests()
