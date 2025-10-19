#!/usr/bin/env python3
"""
Quick fix script to add the missing _mock_capture_loop method
"""

import os
import re

def fix_packet_capture():
    file_path = "app/wifi_core/analyzer.py"
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return False
    
    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if the method already exists
    if '_mock_capture_loop' in content:
        print("_mock_capture_loop method already exists")
        return True
    
    # Find the end of the PacketCapture class and add the method
    mock_method = '''
    def _mock_capture_loop(self):
        """Mock packet capture loop for Windows/simulation mode"""
        import random
        logger.info("Starting mock packet capture loop")
        
        packet_count = 0
        protocols = [ProtocolType.TCP, ProtocolType.UDP, ProtocolType.HTTPS, ProtocolType.DNS]
        
        while self.is_capturing and packet_count < 150:
            try:
                # Generate realistic mock packet
                now = time.time()
                protocol = random.choice(protocols)
                
                packet_info = PacketInfo(
                    timestamp=now,
                    source_ip=f"192.168.1.{random.randint(1, 254)}",
                    dest_ip=f"192.168.1.{random.randint(1, 254)}",
                    source_port=random.randint(1024, 65535),
                    dest_port=random.choice([80, 443, 53, 22, 993, 587, 8080]),
                    protocol=protocol,
                    size=random.randint(64, 1500),
                    flags=["ACK", "PSH"] if protocol == ProtocolType.TCP else [],
                    payload_preview=""
                )
                
                self.packet_queue.append(packet_info)
                packet_count += 1
                
                # Realistic packet timing
                time.sleep(random.uniform(0.01, 0.05))
                
            except Exception as e:
                if self.is_capturing:
                    logger.debug(f"Mock capture loop error: {e}")
                time.sleep(0.01)
        
        logger.info(f"Mock packet capture completed: {packet_count} packets generated")
'''
    
    # Find a good insertion point - before the class ends
    # Look for clear_packets method and add after it
    pattern = r'(\s+def clear_packets\(self\):[^\n]*\n[^\n]*\n[^\n]*\n)'
    
    if re.search(pattern, content):
        # Insert after clear_packets method
        content = re.sub(pattern, r'\1' + mock_method, content)
        
        # Write back to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✓ Successfully added _mock_capture_loop method")
        return True
    else:
        print("Could not find insertion point")
        return False

if __name__ == "__main__":
    success = fix_packet_capture()
    if success:
        print("Packet capture fix applied successfully!")
    else:
        print("Failed to apply packet capture fix")