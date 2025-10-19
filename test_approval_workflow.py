#!/usr/bin/env python3
"""
Test script to verify the approval system workflow
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_approval_workflow():
    """Test the complete approval workflow"""
    try:
        from app import create_app
        from app.models import db
        from app.models.approval_system import (
            AdvancedFeatureRequest, 
            ApprovalSystemManager, 
            ApprovalStatus,
            RequestType,
            Priority
        )
        
        # Create Flask app context
        app = create_app()
        with app.app_context():
            # Create tables
            db.create_all()
            print("✓ Database tables created successfully")
            
            # Test creating a request
            test_request = ApprovalSystemManager.create_request(
                user_id=1,  # Assuming user ID 1 exists
                purpose="Testing the approval system workflow to ensure it works correctly",
                use_case="This is a test use case to verify that form submissions are properly stored and displayed",
                organization="Test Organization",
                organization_role="Developer",
                expected_usage="Testing and development purposes",
                request_type=RequestType.ADVANCED_FEATURES,
                priority=Priority.MEDIUM,
                ip_address="127.0.0.1",
                user_agent="Test Agent"
            )
            print(f"✓ Test request created with ID: {test_request.id}")
            
            # Verify the request was stored
            stored_request = AdvancedFeatureRequest.query.get(test_request.id)
            if stored_request:
                print(f"✓ Request verified in database")
                print(f"  - Status: {stored_request.status.value}")
                print(f"  - Purpose: {stored_request.purpose[:50]}...")
                print(f"  - Created: {stored_request.created_at}")
            else:
                print("✗ Request not found in database")
                return False
            
            # Test getting pending requests
            pending_requests = ApprovalSystemManager.get_pending_requests()
            print(f"✓ Found {len(pending_requests)} pending requests")
            
            return True
            
    except Exception as e:
        print(f"✗ Error testing approval workflow: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_approval_workflow()
    if success:
        print("\n🎉 Approval system workflow test completed successfully!")
    else:
        print("\n❌ Approval system workflow test failed!")
        sys.exit(1)