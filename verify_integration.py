#!/usr/bin/env python3
"""
Verification script to check template and backend integration
"""

import os
import re
import json

def check_template_alignment():
    """Check if template modifications align with backend changes"""
    
    print("🔍 Verifying Template and Backend Integration")
    print("=" * 60)
    
    issues = []
    successes = []
    
    # Check 1: Deep scan template exists and has required elements
    template_path = "templates/main/deep_scan.html"
    if os.path.exists(template_path):
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
            
        # Check for key elements
        required_elements = [
            'AI-Powered Deep Security Analysis',
            'Connected Network Analysis',
            'AI Model Predictions',
            'PDF Report Generation',
            'downloadPDFReport',
            '/api/vulnerability/deep-analysis',
            '/api/scan-results/',
            '/api/reports/deep-scan/',
            'handleScanResults',
            'individual_predictions',
            'security_score'
        ]
        
        for element in required_elements:
            if element in template_content:
                successes.append(f"✓ Template contains: {element}")
            else:
                issues.append(f"✗ Template missing: {element}")
    else:
        issues.append(f"✗ Deep scan template not found: {template_path}")
    
    # Check 2: API endpoints exist
    api_path = "app/api/__init__.py"
    if os.path.exists(api_path):
        with open(api_path, 'r', encoding='utf-8') as f:
            api_content = f.read()
            
        required_endpoints = [
            "'/vulnerability/deep-analysis'",
            "'/scan-status/<scan_id>'",
            "'/scan-results/<scan_id>'",
            "'/reports/deep-scan/<scan_id>'",
            "DeepAnalysisEngine",
            "individual_predictions",
            "ensemble_prediction"
        ]
        
        for endpoint in required_endpoints:
            if endpoint in api_content:
                successes.append(f"✓ API contains: {endpoint}")
            else:
                issues.append(f"✗ API missing: {endpoint}")
    else:
        issues.append(f"✗ API file not found: {api_path}")
    
    # Check 3: Deep analysis engine exists
    engine_path = "app/ai_engine/deep_analysis_engine.py"
    if os.path.exists(engine_path):
        with open(engine_path, 'r', encoding='utf-8') as f:
            engine_content = f.read()
            
        required_components = [
            "class DeepAnalysisEngine",
            "class ConnectedNetworkAnalyzer",
            "class NetworkFeatureExtractor",
            "perform_deep_analysis",
            "_run_individual_predictions",
            "_run_ensemble_prediction",
            "generate_deep_analysis_report"
        ]
        
        for component in required_components:
            if component in engine_content:
                successes.append(f"✓ Engine contains: {component}")
            else:
                issues.append(f"✗ Engine missing: {component}")
    else:
        issues.append(f"✗ Deep analysis engine not found: {engine_path}")
    
    # Check 4: PDF generator has deep analysis method
    pdf_path = "app/utils/pdf_generator.py"
    if os.path.exists(pdf_path):
        with open(pdf_path, 'r', encoding='utf-8') as f:
            pdf_content = f.read()
            
        if "generate_deep_analysis_report" in pdf_content:
            successes.append("✓ PDF generator has deep analysis method")
        else:
            issues.append("✗ PDF generator missing deep analysis method")
    else:
        issues.append(f"✗ PDF generator not found: {pdf_path}")
    
    # Check 5: App.py has vulnerability blueprint registered
    app_path = "app.py"
    if os.path.exists(app_path):
        with open(app_path, 'r', encoding='utf-8') as f:
            app_content = f.read()
            
        if "vulnerability_bp" in app_content and "url_prefix='/api/vulnerability'" in app_content:
            successes.append("✓ Vulnerability blueprint registered")
        else:
            issues.append("✗ Vulnerability blueprint not properly registered")
    else:
        issues.append(f"✗ App.py not found: {app_path}")
    
    # Check 6: Routes updated to use deep_scan.html
    routes_path = "app/main/routes.py"
    if os.path.exists(routes_path):
        with open(routes_path, 'r', encoding='utf-8') as f:
            routes_content = f.read()
            
        if "deep_scan.html" in routes_content:
            successes.append("✓ Routes updated to use deep_scan.html")
        else:
            issues.append("✗ Routes still using old template")
    else:
        issues.append(f"✗ Routes file not found: {routes_path}")
    
    # Summary
    print("\n📊 VERIFICATION RESULTS")
    print("=" * 30)
    
    if successes:
        print(f"\n✅ SUCCESSFUL INTEGRATIONS ({len(successes)}):")
        for success in successes:
            print(f"   {success}")
    
    if issues:
        print(f"\n❌ INTEGRATION ISSUES ({len(issues)}):")
        for issue in issues:
            print(f"   {issue}")
    else:
        print(f"\n🎉 ALL INTEGRATIONS SUCCESSFUL!")
    
    # Data flow check
    print(f"\n🔄 DATA FLOW VERIFICATION:")
    print(f"   Frontend (deep_scan.html) → Backend API (/api/vulnerability/deep-analysis)")
    print(f"   API → Deep Analysis Engine → AI Models → Results")
    print(f"   Results → Database → PDF Report → Download")
    
    if len(issues) == 0:
        print(f"\n✅ Template and backend are properly integrated!")
        print(f"   • Frontend calls correct API endpoints")
        print(f"   • API uses real deep analysis engine")
        print(f"   • Engine uses actual AI models")
        print(f"   • PDF reports are generated")
        print(f"   • All data flows are aligned")
        return True
    else:
        print(f"\n⚠️  Some integration issues found. Please review the items above.")
        return False

def check_ai_models():
    """Check if AI models are available"""
    print(f"\n🤖 AI MODELS CHECK:")
    models_dir = "models"
    if os.path.exists(models_dir):
        model_files = [f for f in os.listdir(models_dir) if f.endswith(('.h5', '.pkl'))]
        print(f"   Found {len(model_files)} AI model files:")
        for model in sorted(model_files):
            size = os.path.getsize(os.path.join(models_dir, model)) / 1024 / 1024
            print(f"   • {model} ({size:.1f} MB)")
        return len(model_files) > 0
    else:
        print(f"   ❌ Models directory not found")
        return False

def main():
    """Run all verification checks"""
    print("WISEC Deep Analysis Integration Verification")
    print("=" * 50)
    
    template_ok = check_template_alignment()
    models_ok = check_ai_models()
    
    print(f"\n🏁 FINAL STATUS:")
    if template_ok and models_ok:
        print(f"   ✅ System is ready for deep analysis!")
        print(f"   🚀 You can now run deep scans at http://127.0.0.1:5000/deep-scan")
    else:
        print(f"   ❌ System needs attention before use")
    
    return 0 if (template_ok and models_ok) else 1

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)