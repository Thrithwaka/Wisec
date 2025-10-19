#!/usr/bin/env python3
"""
Debug script to check what requests exist in the database
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def debug_requests():
    """Debug what requests exist"""
    try:
        print("Checking approval requests in database...")
        
        # Try importing without full app setup first
        from app.models.approval_system import AdvancedFeatureRequest, ApprovalStatus
        from app.models import db
        from app import create_app
        
        # Create minimal app context
        app = create_app()
        with app.app_context():
            # Check if tables exist
            try:
                total_requests = AdvancedFeatureRequest.query.count()
                print(f"✓ Total requests in database: {total_requests}")
                
                if total_requests > 0:
                    # Show all requests
                    all_requests = AdvancedFeatureRequest.query.all()
                    print("\n📋 All requests:")
                    for req in all_requests:
                        print(f"  - ID: {req.id}")
                        print(f"    User ID: {req.user_id}")
                        print(f"    Status: {req.status.value}")
                        print(f"    Purpose: {req.purpose[:50]}...")
                        print(f"    Created: {req.created_at}")
                        print(f"    Priority: {req.priority.value}")
                        print("    ---")
                
                # Check each status count
                pending = AdvancedFeatureRequest.query.filter_by(status=ApprovalStatus.PENDING).count()
                under_review = AdvancedFeatureRequest.query.filter_by(status=ApprovalStatus.UNDER_REVIEW).count()
                approved = AdvancedFeatureRequest.query.filter_by(status=ApprovalStatus.APPROVED).count()
                rejected = AdvancedFeatureRequest.query.filter_by(status=ApprovalStatus.REJECTED).count()
                
                print(f"\n📊 Status breakdown:")
                print(f"  - Pending: {pending}")
                print(f"  - Under Review: {under_review}")
                print(f"  - Approved: {approved}")
                print(f"  - Rejected: {rejected}")
                
            except Exception as db_error:
                print(f"✗ Database query error: {db_error}")
                return False
                
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"✗ General error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = debug_requests()
    if not success:
        sys.exit(1)