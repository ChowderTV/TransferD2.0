#!/usr/bin/env python3
"""
Security test script for TransferD 2.0
Tests the security functions we've implemented
"""

import sys
import os
sys.path.append('.')

from transfer_app import sanitize_filename, validate_ip_port, sanitize_text_message

def test_filename_sanitization():
    """Test filename sanitization"""
    print("Testing filename sanitization...")
    
    # Test cases
    test_cases = [
        ("../../../etc/passwd", "file_"),  # Path traversal
        ("normal_file.txt", "normal_file.txt"),  # Normal file
        ("<script>alert('xss')</script>.txt", "_script_alert__xss___script_.txt"),  # XSS attempt
        ("", "unnamed_file"),  # Empty filename
        (".", "file_"),  # Current directory
        ("..", "file_"),  # Parent directory
        ("file\x00name.txt", "filename.txt"),  # Null byte
        ("a" * 300 + ".txt", "a" * 250 + ".txt"),  # Long filename
    ]
    
    for original, expected_prefix in test_cases:
        result = sanitize_filename(original)
        print(f"  '{original}' -> '{result}'")
        
        # Check that result doesn't contain path traversal
        assert ".." not in result
        assert "/" not in result
        assert "\\" not in result
        assert "\x00" not in result
        
        # Check length limit
        assert len(result) <= 255
    
    print("✓ Filename sanitization tests passed")

def test_ip_validation():
    """Test IP address validation"""
    print("\nTesting IP validation...")
    
    test_cases = [
        ("192.168.1.1", "192.168.1.1:8080"),  # Valid IP
        ("192.168.1.1:9000", "192.168.1.1:9000"),  # Valid IP with port
        ("256.1.1.1", None),  # Invalid IP (> 255)
        ("192.168.1", None),  # Incomplete IP
        ("192.168.1.1:70000", None),  # Invalid port (> 65535)
        ("192.168.1.1:abc", None),  # Non-numeric port
        ("", None),  # Empty input
        ("Enter IP:Port", None),  # Placeholder text
    ]
    
    for input_ip, expected in test_cases:
        result = validate_ip_port(input_ip)
        print(f"  '{input_ip}' -> '{result}'")
        assert result == expected
    
    print("✓ IP validation tests passed")

def test_text_sanitization():
    """Test text message sanitization"""
    print("\nTesting text sanitization...")
    
    test_cases = [
        ("Hello World", "Hello World"),  # Normal text
        ("Test\x00message", "Testmessage"),  # Null byte removal
        ("Line1\nLine2\tTabbed", "Line1\nLine2\tTabbed"),  # Keep newlines and tabs
        ("A" * 15000, "A" * 10000),  # Length limit
        ("", ""),  # Empty text
        ("Control\x01chars\x1fremoved", "Controlcharsremoved"),  # Control chars
    ]
    
    for original, expected in test_cases:
        result = sanitize_text_message(original)
        print(f"  Length {len(original)} -> Length {len(result)}")
        
        # Check length limit
        assert len(result) <= 10000
        
        # Check no control characters (except \n and \t)
        for char in result:
            if ord(char) < 32 and char not in '\n\t':
                assert False, f"Found control character: {repr(char)}"
    
    print("✓ Text sanitization tests passed")

if __name__ == "__main__":
    print("Running TransferD 2.0 Security Tests")
    print("=" * 40)
    
    test_filename_sanitization()
    test_ip_validation()
    test_text_sanitization()
    
    print("\n🎉 All security tests passed!")
    print("The security fixes are working correctly.")