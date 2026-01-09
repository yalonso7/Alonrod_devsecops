#!/usr/bin/env python3
"""
Test suite for security_utils module
"""

import unittest
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from security_utils import (
    validate_api_url, sanitize_policy_name, is_private_ip,
    SecureTokenManager, RBACManager, ThreatDetector,
    SecretsManager, RateLimiter, CircuitBreaker, MetricsCollector
)


class TestURLValidation(unittest.TestCase):
    """Test URL validation functions"""
    
    def test_valid_prisma_url(self):
        """Test valid Prisma Cloud URLs"""
        self.assertTrue(validate_api_url("https://api.prismacloud.io"))
        self.assertTrue(validate_api_url("https://app.prismacloud.io"))
        self.assertTrue(validate_api_url("https://console.prismacloud.io"))
    
    def test_invalid_url(self):
        """Test invalid URLs"""
        self.assertFalse(validate_api_url("https://evil.com"))
        self.assertFalse(validate_api_url("http://localhost"))
        self.assertFalse(validate_api_url("https://192.168.1.1"))


class TestInputSanitization(unittest.TestCase):
    """Test input sanitization functions"""
    
    def test_valid_policy_name(self):
        """Test valid policy names"""
        self.assertEqual(sanitize_policy_name("test-policy_123"), "test-policy_123")
        self.assertEqual(sanitize_policy_name("MyPolicy"), "MyPolicy")
    
    def test_invalid_policy_name(self):
        """Test invalid policy names"""
        with self.assertRaises(ValueError):
            sanitize_policy_name("test policy")  # Space not allowed
        with self.assertRaises(ValueError):
            sanitize_policy_name("test@policy")  # Special char not allowed
        with self.assertRaises(ValueError):
            sanitize_policy_name("")  # Empty not allowed


class TestSecureTokenManager(unittest.TestCase):
    """Test SecureTokenManager"""
    
    def test_token_expiration(self):
        """Test token expiration logic"""
        manager = SecureTokenManager(token_ttl=1)  # 1 second TTL
        manager.set_token("test-token")
        self.assertFalse(manager.is_token_expired())
        self.assertEqual(manager.get_valid_token(), "test-token")
    
    def test_expired_token(self):
        """Test expired token handling"""
        manager = SecureTokenManager(token_ttl=-1)  # Already expired
        manager.set_token("test-token")
        self.assertTrue(manager.is_token_expired())
        self.assertIsNone(manager.get_valid_token())


class TestThreatDetector(unittest.TestCase):
    """Test ThreatDetector"""
    
    def test_anomaly_detection(self):
        """Test anomaly detection"""
        detector = ThreatDetector(anomaly_threshold=5, time_window=60)
        
        # Record multiple requests
        for i in range(10):
            detector.record_request({
                'endpoint': 'policy',
                'method': 'GET',
                'source_ip': '192.168.1.1',
                'user': 'test'
            })
        
        # Check for anomalies
        anomalies = detector.detect_anomalies({
            'endpoint': 'policy',
            'method': 'GET',
            'source_ip': '192.168.1.1',
            'user': 'test'
        })
        
        # Should detect rate limit exceeded
        self.assertIn("RATE_LIMIT_EXCEEDED", anomalies)


class TestRateLimiter(unittest.TestCase):
    """Test RateLimiter"""
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        limiter = RateLimiter(max_calls=2, period=1.0)
        
        # First two calls should succeed
        with limiter:
            pass
        with limiter:
            pass
        
        # Third call should be rate limited (will sleep)
        import time
        start = time.time()
        with limiter:
            pass
        duration = time.time() - start
        
        # Should have slept for some time
        self.assertGreater(duration, 0.1)


class TestMetricsCollector(unittest.TestCase):
    """Test MetricsCollector"""
    
    def test_metrics_collection(self):
        """Test metrics collection"""
        collector = MetricsCollector()
        
        collector.record_api_request(True, 0.5)
        collector.record_api_request(False, 1.0)
        collector.record_authentication(True)
        collector.record_deployment(True)
        collector.record_security_event()
        
        metrics = collector.get_metrics()
        
        self.assertEqual(metrics['api_requests_total'], 2)
        self.assertEqual(metrics['api_requests_failed'], 1)
        self.assertEqual(metrics['authentication_attempts'], 1)
        self.assertEqual(metrics['deployments_total'], 1)
        self.assertEqual(metrics['security_events'], 1)
        self.assertGreater(metrics['response_time_avg'], 0)


class TestSecretsManager(unittest.TestCase):
    """Test SecretsManager"""
    
    def test_env_secrets(self):
        """Test environment variable secrets"""
        import os
        os.environ['TEST_SECRET'] = 'test-value'
        
        manager = SecretsManager(provider='env')
        secret = manager.get_secret('TEST_SECRET')
        
        self.assertEqual(secret, 'test-value')
        
        # Cleanup
        del os.environ['TEST_SECRET']


if __name__ == '__main__':
    unittest.main()
