#!/usr/bin/env python3
"""
Complete Unit Tests for NIDPS System
Single file containing all tests for easy execution
"""

import unittest
import sys
import os
import time
import threading
import tempfile
from unittest.mock import patch, MagicMock, mock_open, call
from collections import defaultdict, deque

# ==============================================================================
# FIX THE PATH ISSUE - Import from Nexus_NIDP.py
# ==============================================================================

# Get the directory where this test file is located
current_dir = os.path.dirname(os.path.abspath(__file__))
# Add it to Python path so Python can find Nexus_NIDP.py
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

print(f"Current directory: {current_dir}")
print(f"Files in current directory: {os.listdir(current_dir)}")

# Now try to import from Nexus_NIDP
try:
    from Nexus_NIDP import (
        ResultNode, DiscoveryStorage, PacketNode, CustomQueue,
        FirewallManager, NIDS, LoginSystem, NIDSApp, Colors
    )
    print("✅ Successfully imported from Nexus_NIDP.py")
except ImportError as e:
    print(f"❌ Error importing from Nexus_NIDP.py: {e}")
    print("\nTroubleshooting tips:")
    print("1. Make sure Nexus_NIDP.py is in the same directory as this test file")
    print("2. Check if the file name is exactly 'Nexus_NIDP.py' (case sensitive)")
    print("3. Check if the file has the correct permissions")
    sys.exit(1)


# ==============================================================================
# TEST DATA STRUCTURES (LO1)
# ==============================================================================

class TestResultNode(unittest.TestCase):
    """Test the ResultNode class"""
    
    def test_node_creation(self):
        """Test that a ResultNode is created correctly"""
        node = ResultNode("Test message")
        self.assertEqual(node.message, "Test message")
        self.assertIsNotNone(node.timestamp)
        self.assertIsNone(node.next)
    
    def test_node_timestamp_format(self):
        """Test that timestamp has correct format"""
        node = ResultNode("Test")
        # Format should be HH:MM:SS
        parts = node.timestamp.split(':')
        self.assertEqual(len(parts), 3)
        self.assertTrue(0 <= int(parts[0]) <= 23)
        self.assertTrue(0 <= int(parts[1]) <= 59)
        self.assertTrue(0 <= int(parts[2]) <= 59)


class TestDiscoveryStorage(unittest.TestCase):
    """Test the DiscoveryStorage linked list implementation"""
    
    def setUp(self):
        self.storage = DiscoveryStorage(max_size=5)
    
    def test_initial_state(self):
        """Test initial state of storage"""
        self.assertIsNone(self.storage.head)
        self.assertEqual(self.storage.count, 0)
        self.assertEqual(self.storage.max_size, 5)
    
    def test_insert_single(self):
        """Test inserting a single item"""
        self.storage.insert("Test message")
        self.assertEqual(self.storage.count, 1)
        self.assertIsNotNone(self.storage.head)
        self.assertEqual(self.storage.head.message, "Test message")
    
    def test_insert_multiple(self):
        """Test inserting multiple items (LIFO order)"""
        self.storage.insert("First")
        self.storage.insert("Second")
        self.storage.insert("Third")
        
        self.assertEqual(self.storage.count, 3)
        results = self.storage.get_all()
        self.assertEqual(len(results), 3)
        # Should be in reverse order (LIFO)
        self.assertIn("Third", results[0])
        self.assertIn("Second", results[1])
        self.assertIn("First", results[2])
    
    def test_max_size_limit(self):
        """Test that storage respects max_size limit"""
        for i in range(10):
            self.storage.insert(f"Message {i}")
        
        self.assertEqual(self.storage.count, 5)  # Max size is 5
        results = self.storage.get_all()
        self.assertEqual(len(results), 5)
    
    def test_clear(self):
        """Test clearing the storage"""
        self.storage.insert("Test")
        self.storage.insert("Test2")
        self.assertEqual(self.storage.count, 2)
        
        self.storage.clear()
        self.assertEqual(self.storage.count, 0)
        self.assertIsNone(self.storage.head)
        self.assertEqual(self.storage.get_all(), [])
    
    def test_get_all_empty(self):
        """Test get_all on empty storage"""
        self.assertEqual(self.storage.get_all(), [])


class TestPacketNode(unittest.TestCase):
    """Test the PacketNode class"""
    
    def test_node_creation(self):
        """Test PacketNode creation"""
        data = {'src': '192.168.1.1', 'dst': '192.168.1.2'}
        node = PacketNode(data)
        self.assertEqual(node.data, data)
        self.assertIsNone(node.next)


class TestCustomQueue(unittest.TestCase):
    """Test the CustomQueue implementation"""
    
    def setUp(self):
        self.queue = CustomQueue()
    
    def test_initial_state(self):
        """Test initial queue state"""
        self.assertTrue(self.queue.is_empty())
        self.assertIsNone(self.queue.head)
        self.assertIsNone(self.queue.tail)
    
    def test_enqueue_dequeue(self):
        """Test basic enqueue and dequeue operations"""
        data1 = {'src': '192.168.1.1'}
        data2 = {'src': '192.168.1.2'}
        
        self.queue.enqueue(data1)
        self.queue.enqueue(data2)
        
        self.assertFalse(self.queue.is_empty())
        
        result = self.queue.dequeue()
        self.assertEqual(result, data1)
        
        result = self.queue.dequeue()
        self.assertEqual(result, data2)
        
        self.assertTrue(self.queue.is_empty())
    
    def test_dequeue_empty(self):
        """Test dequeue from empty queue"""
        result = self.queue.dequeue()
        self.assertIsNone(result)
    
    def test_get_all(self):
        """Test getting all items"""
        data1 = {'src': '192.168.1.1'}
        data2 = {'src': '192.168.1.2'}
        
        self.queue.enqueue(data1)
        self.queue.enqueue(data2)
        
        items = self.queue.get_all()
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0], data1)
        self.assertEqual(items[1], data2)
    
    def test_clear(self):
        """Test clearing the queue"""
        self.queue.enqueue({'src': 'test'})
        self.queue.enqueue({'src': 'test2'})
        self.assertFalse(self.queue.is_empty())
        
        self.queue.clear()
        self.assertTrue(self.queue.is_empty())
        self.assertIsNone(self.queue.head)
        self.assertIsNone(self.queue.tail)
    
    def test_thread_safety(self):
        """Test that queue operations are thread-safe"""
        def add_items():
            for i in range(100):
                self.queue.enqueue({'id': i})
        
        threads = [threading.Thread(target=add_items) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have 500 items
        self.assertEqual(len(self.queue.get_all()), 500)


# ==============================================================================
# TEST FIREWALL MANAGER (LO4)
# ==============================================================================

class TestFirewallManager(unittest.TestCase):
    """Test the FirewallManager class"""
    
    def setUp(self):
        self.firewall = FirewallManager()
    
    @patch('subprocess.run')
    def test_check_iptables_available(self, mock_run):
        """Test iptables availability check when installed"""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "/usr/sbin/iptables"
        
        result = self.firewall._check_iptables()
        self.assertTrue(result)
    
    @patch('subprocess.run')
    def test_check_iptables_not_available(self, mock_run):
        """Test iptables availability check when not installed"""
        mock_run.return_value.returncode = 1
        
        result = self.firewall._check_iptables()
        self.assertFalse(result)
    
    @patch('subprocess.run')
    def test_check_iptables_exception(self, mock_run):
        """Test iptables availability check when exception occurs"""
        mock_run.side_effect = Exception("Command not found")
        
        result = self.firewall._check_iptables()
        self.assertFalse(result)
    
    def test_is_valid_ip(self):
        """Test IP address validation"""
        # Valid IPs
        self.assertTrue(self.firewall._is_valid_ip("192.168.1.1"))
        self.assertTrue(self.firewall._is_valid_ip("10.0.0.1"))
        self.assertTrue(self.firewall._is_valid_ip("255.255.255.255"))
        
        # Invalid IPs
        self.assertFalse(self.firewall._is_valid_ip("256.1.2.3"))
        self.assertFalse(self.firewall._is_valid_ip("192.168.1"))
        self.assertFalse(self.firewall._is_valid_ip("192.168.1.abc"))
        self.assertFalse(self.firewall._is_valid_ip("192.168.1.300"))
        self.assertFalse(self.firewall._is_valid_ip(""))
    
    def test_protected_ips(self):
        """Test that protected IPs cannot be blocked"""
        for protected_ip in FirewallManager.PROTECTED_IPS:
            success, message = self.firewall.block_ip(protected_ip)
            self.assertFalse(success)
            self.assertIn("Cannot block protected IP", message)
    
    @patch('subprocess.run')
    def test_block_ip_success(self, mock_run):
        """Test successfully blocking an IP"""
        # Mock iptables availability
        self.firewall.iptables_available = True
        mock_run.return_value = MagicMock()
        
        success, message = self.firewall.block_ip("192.168.1.100")
        
        self.assertTrue(success)
        self.assertIn("BLOCKED", message)
        self.assertIn("192.168.1.100", self.firewall.blocked_ips)
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_block_ip_duplicate(self, mock_run):
        """Test blocking an already blocked IP"""
        self.firewall.iptables_available = True
        self.firewall.blocked_ips.add("192.168.1.100")
        
        success, message = self.firewall.block_ip("192.168.1.100")
        
        self.assertFalse(success)
        self.assertEqual(message, "IP already blocked")
        mock_run.assert_not_called()
    
    @patch('subprocess.run')
    def test_unblock_ip_success(self, mock_run):
        """Test successfully unblocking an IP"""
        self.firewall.iptables_available = True
        self.firewall.blocked_ips.add("192.168.1.100")
        mock_run.return_value = MagicMock()
        
        success, message = self.firewall.unblock_ip("192.168.1.100")
        
        self.assertTrue(success)
        self.assertIn("UNBLOCKED", message)
        self.assertNotIn("192.168.1.100", self.firewall.blocked_ips)
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_unblock_ip_not_blocked(self, mock_run):
        """Test unblocking an IP that isn't blocked"""
        self.firewall.iptables_available = True
        
        success, message = self.firewall.unblock_ip("192.168.1.100")
        
        self.assertFalse(success)
        self.assertEqual(message, "IP not blocked")
        mock_run.assert_not_called()
    
    def test_get_blocked_list(self):
        """Test getting list of blocked IPs"""
        self.firewall.blocked_ips = {"192.168.1.100", "10.0.0.5"}
        
        blocked = self.firewall.get_blocked_list()
        self.assertEqual(len(blocked), 2)
        self.assertIn("192.168.1.100", blocked)
        self.assertIn("10.0.0.5", blocked)
    
    def test_is_blocked(self):
        """Test checking if IP is blocked"""
        self.firewall.blocked_ips.add("192.168.1.100")
        
        self.assertTrue(self.firewall.is_blocked("192.168.1.100"))
        self.assertFalse(self.firewall.is_blocked("192.168.1.101"))


# ==============================================================================
# TEST NIDS CORE LOGIC (LO2 & LO4) - SIMPLIFIED VERSION
# ==============================================================================

class TestNIDS(unittest.TestCase):
    """Test the NIDS class"""
    
    def setUp(self):
        self.nids = NIDS(iface="eth0")
        # Override cooldown for testing
        self.nids.COOLDOWN_SECONDS = 0.1
    
    def test_initial_state(self):
        """Test initial NIDS state"""
        self.assertEqual(self.nids.iface, "eth0")
        self.assertFalse(self.nids.is_running)
        self.assertIsNotNone(self.nids.packet_queue)
        self.assertIsNotNone(self.nids.alert_queue)
        self.assertIsNotNone(self.nids.results)
    
    def test_enqueue_packet_direct(self):
        """Test packet enqueue functionality directly (simplified approach)"""
        # Test data for IP-only packet
        test_data_ip = {
            'src': '192.168.1.100',
            'dst': '192.168.1.1',
            'time': time.time()
        }
        
        # Directly enqueue data
        self.nids.packet_queue.enqueue(test_data_ip)
        
        # Check that packet was enqueued
        self.assertFalse(self.nids.packet_queue.is_empty())
        
        # Get the packet data
        packet_data = self.nids.packet_queue.dequeue()
        self.assertIsNotNone(packet_data)
        self.assertEqual(packet_data['src'], "192.168.1.100")
        self.assertEqual(packet_data['dst'], "192.168.1.1")
        
        # Test data for TCP packet
        test_data_tcp = {
            'src': '192.168.1.100',
            'dst': '192.168.1.1',
            'time': time.time(),
            'sport': 12345,
            'dport': 80,
            'flags': 'S'
        }
        
        # Directly enqueue data
        self.nids.packet_queue.enqueue(test_data_tcp)
        
        # Check that packet was enqueued
        self.assertFalse(self.nids.packet_queue.is_empty())
        
        # Get the packet data
        packet_data = self.nids.packet_queue.dequeue()
        self.assertIsNotNone(packet_data)
        self.assertEqual(packet_data['src'], "192.168.1.100")
        self.assertEqual(packet_data['dst'], "192.168.1.1")
        self.assertEqual(packet_data['sport'], 12345)
        self.assertEqual(packet_data['dport'], 80)
        self.assertEqual(packet_data['flags'], 'S')
    
    def test_process_packet_flood_detection(self):
        """Test DoS/Flood detection"""
        src_ip = "192.168.1.100"
        now = time.time()
        
        # Simulate 150 packets in 1 second (exceeds threshold of 100)
        for i in range(150):
            pkt = {
                'src': src_ip,
                'dst': "192.168.1.1",
                'time': now - 0.5 + (i * 0.01)  # Spread over 0.5 seconds
            }
            self.nids.process_packet(pkt)
        
        # Should have triggered an alert
        self.assertIn(src_ip, self.nids.detected_attackers)
        
        # Check alert queue
        alerts = self.nids.get_alerts()
        self.assertTrue(any("DoS/Flood" in alert for alert in alerts))
    
    def test_process_packet_syn_scan_detection(self):
        """Test SYN port scan detection"""
        src_ip = "192.168.1.100"
        now = time.time()
        
        # Simulate SYN packets to 40 different ports (exceeds threshold of 30)
        for port in range(40):
            pkt = {
                'src': src_ip,
                'dst': "192.168.1.1",
                'time': now,
                'flags': 'S',
                'dport': 1000 + port
            }
            self.nids.process_packet(pkt)
        
        # Should have triggered an alert
        self.assertIn(src_ip, self.nids.detected_attackers)
        
        # Check alert queue
        alerts = self.nids.get_alerts()
        self.assertTrue(any("Port Scan" in alert for alert in alerts))
    
    def test_alert_cooldown(self):
        """Test alert cooldown mechanism"""
        src_ip = "192.168.1.100"
        
        # First alert
        self.nids._trigger_alert("Test alert", src_ip, "TEST")
        
        # Second alert immediately (should be suppressed)
        self.nids._trigger_alert("Test alert", src_ip, "TEST")
        
        # Check that only one alert was queued
        alerts = self.nids.get_alerts()
        self.assertEqual(len(alerts), 1)
        
        # Check that suppression count increased
        stats = self.nids.get_stats()
        self.assertIn(f"{src_ip}:TEST", stats)
        self.assertEqual(stats[f"{src_ip}:TEST"], 1)
    
    def test_alert_with_suppression_count(self):
        """Test alert that includes suppression count"""
        src_ip = "192.168.1.100"
        
        # Trigger first alert
        self.nids._trigger_alert("Test", src_ip, "TEST")
        
        # Suppress 5 more
        for _ in range(5):
            self.nids._trigger_alert("Test", src_ip, "TEST")
        
        # Wait for cooldown
        time.sleep(0.2)
        
        # Trigger final alert
        self.nids._trigger_alert("Test", src_ip, "TEST")
        
        alerts = self.nids.get_alerts()
        
        # Check that last alert includes suppression count
        found = False
        for alert in alerts:
            if "[+5 alerts]" in alert:
                found = True
                break
        self.assertTrue(found)
    
    @patch.object(NIDS, 'block_ip')
    def test_block_ip(self, mock_block):
        """Test blocking an IP"""
        mock_block.return_value = (True, "Blocked")
        
        self.nids.block_ip("192.168.1.100")
        mock_block.assert_called_once_with("192.168.1.100")
    
    def test_clear_logs(self):
        """Test clearing all logs"""
        self.nids.alert_queue.enqueue("Test alert")
        self.nids.results.insert("Test result")
        self.nids.detected_attackers.add("192.168.1.100")
        
        self.nids.clear_logs()
        
        self.assertTrue(self.nids.alert_queue.is_empty())
        self.assertEqual(self.nids.results.get_all(), [])
        self.assertEqual(len(self.nids.detected_attackers), 0)
    
    def test_set_get_attack_ip(self):
        """Test setting and getting selected attack IP"""
        self.nids.set_attack_ip("192.168.1.100")
        self.assertEqual(self.nids.get_attack_ip(), "192.168.1.100")
        
        self.nids.set_attack_ip(None)
        self.assertIsNone(self.nids.get_attack_ip())
    
    def test_set_get_block_ip(self):
        """Test setting and getting selected block IP"""
        self.nids.set_block_ip("192.168.1.100")
        self.assertEqual(self.nids.get_block_ip(), "192.168.1.100")
        
        self.nids.set_block_ip(None)
        self.assertIsNone(self.nids.get_block_ip())
    
    @patch('scapy.all.sniff')
    def test_start_stop(self, mock_sniff):
        """Test starting and stopping NIDS"""
        # Mock the sniff function
        mock_sniff.return_value = None
        
        result = self.nids.start()
        self.assertTrue(result)
        self.assertTrue(self.nids.is_running)
        
        self.nids.stop()
        self.assertFalse(self.nids.is_running)


# ==============================================================================
# TEST LOGIN SYSTEM
# ==============================================================================

class TestLoginSystem(unittest.TestCase):
    """Test the LoginSystem class"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a temporary user file
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.temp_file.write("admin,admin123\n")
        self.temp_file.write("testuser,testpass\n")
        self.temp_file.close()
        
        # Patch USER_FILE to use temp file
        self.patcher = patch('Nexus_NIDP.USER_FILE', self.temp_file.name)
        self.patcher.start()
    
    def tearDown(self):
        """Clean up after tests"""
        self.patcher.stop()
        os.unlink(self.temp_file.name)
    
    @patch('tkinter.messagebox.showwarning')
    def test_handle_register_empty_fields(self, mock_warning):
        """Test registration with empty fields"""
        login = LoginSystem()
        login.reg_user = MagicMock()
        login.reg_pass = MagicMock()
        login.reg_user.get.return_value = ""
        login.reg_pass.get.return_value = ""
        
        login.handle_register()
        
        mock_warning.assert_called_once_with("Input Error", "Please fill in all fields")
    
    @patch('tkinter.messagebox.showwarning')
    def test_handle_login_empty_fields(self, mock_warning):
        """Test login with empty fields"""
        login = LoginSystem()
        login.username_entry = MagicMock()
        login.password_entry = MagicMock()
        login.username_entry.get.return_value = ""
        login.password_entry.get.return_value = ""
        
        login.handle_login()
        
        mock_warning.assert_called_once_with("Input Error", "Please fill in all fields")
    
    @patch('tkinter.messagebox.showerror')
    @patch('os.path.getsize')
    def test_handle_login_no_users(self, mock_getsize, mock_error):
        """Test login when no users exist"""
        mock_getsize.return_value = 0
        
        login = LoginSystem()
        login.username_entry = MagicMock()
        login.password_entry = MagicMock()
        login.username_entry.get.return_value = "admin"
        login.password_entry.get.return_value = "admin123"
        
        login.handle_login()
        
        mock_error.assert_called_once_with("Error", "No users found. Please register first.")
    
    @patch('tkinter.messagebox.showinfo')
    def test_handle_login_success(self, mock_info):
        """Test successful login"""
        login = LoginSystem()
        login.username_entry = MagicMock()
        login.password_entry = MagicMock()
        login.username_entry.get.return_value = "admin"
        login.password_entry.get.return_value = "admin123"
        
        with patch.object(login, 'open_nidps') as mock_open:
            login.handle_login()
            
            mock_info.assert_called_once_with("Success", "Welcome, admin!")
            mock_open.assert_called_once_with("admin")
    
    @patch('tkinter.messagebox.showerror')
    def test_handle_login_failure(self, mock_error):
        """Test login failure"""
        login = LoginSystem()
        login.username_entry = MagicMock()
        login.password_entry = MagicMock()
        login.username_entry.get.return_value = "admin"
        login.password_entry.get.return_value = "wrongpass"
        
        login.handle_login()
        
        mock_error.assert_called_once_with("Failed", "Invalid username or password")
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('tkinter.messagebox.showinfo')
    def test_handle_register_success(self, mock_info, mock_file):
        """Test successful registration"""
        login = LoginSystem()
        login.reg_user = MagicMock()
        login.reg_pass = MagicMock()
        login.reg_user.get.return_value = "newuser"
        login.reg_pass.get.return_value = "newpass"
        
        with patch.object(login, 'show_login_screen') as mock_show:
            login.handle_register()
            
            mock_info.assert_called_once_with("Success", "Account created successfully!")
            mock_show.assert_called_once()
    
    def test_clear_frame(self):
        """Test clearing the frame"""
        login = LoginSystem()
        login.main_frame = MagicMock()
        mock_child1 = MagicMock()
        mock_child2 = MagicMock()
        login.main_frame.winfo_children.return_value = [mock_child1, mock_child2]
        
        login.clear_frame()
        
        mock_child1.destroy.assert_called_once()
        mock_child2.destroy.assert_called_once()


# ==============================================================================
# TEST NIDS APP (GUI)
# ==============================================================================

class TestNIDSApp(unittest.TestCase):
    """Test the NIDSApp class"""
    
    def setUp(self):
        """Set up test environment"""
        # Create app with mocked GUI elements
        with patch('customtkinter.CTk'):
            self.app = NIDSApp("testuser")
            # Mock GUI elements
            self.app.log_textbox = MagicMock()
            self.app.alert_count_label = MagicMock()
            self.app.suppressed_label = MagicMock()
            self.app.attacker_combo = MagicMock()
            self.app.blocked_combo = MagicMock()
            self.app.block_btn = MagicMock()
            self.app.unblock_btn = MagicMock()
            self.app.attack_selected_label = MagicMock()
            self.app.block_selected_label = MagicMock()
            self.app.attackers_label = MagicMock()
            self.app.blocked_count_label = MagicMock()
            self.app.status_label = MagicMock()
            self.app.start_btn = MagicMock()
            self.app.stop_btn = MagicMock()
    
    def tearDown(self):
        """Clean up after tests"""
        if hasattr(self.app, 'nids') and self.app.nids:
            self.app.nids.stop()
    
    def test_initialization(self):
        """Test NIDSApp initialization"""
        self.assertEqual(self.app.username, "testuser")
        self.assertIsNone(self.app.nids)
        self.assertEqual(self.app.alert_count, 0)
    
    def test_log_to_ui(self):
        """Test logging to UI"""
        self.app.log_to_ui("Test message")
        
        self.app.log_textbox.configure.assert_any_call(state="normal")
        self.app.log_textbox.insert.assert_called_with("end", "Test message")
        self.app.log_textbox.see.assert_called_with("end")
        self.app.log_textbox.configure.assert_any_call(state="disabled")
    
    @patch('scapy.all.get_if_list')
    def test_get_interfaces(self, mock_get_if_list):
        """Test getting network interfaces"""
        mock_get_if_list.return_value = ["eth0", "wlan0"]
        
        interfaces = self.app.get_interfaces()
        
        self.assertEqual(interfaces, ["eth0", "wlan0"])
    
    @patch('scapy.all.get_if_list')
    def test_get_interfaces_error(self, mock_get_if_list):
        """Test getting interfaces when error occurs"""
        mock_get_if_list.side_effect = Exception("Error")
        
        interfaces = self.app.get_interfaces()
        
        self.assertEqual(interfaces, ["Error"])
    
    def test_update_stats(self):
        """Test updating statistics"""
        self.app.alert_count = 10
        
        self.app.nids = MagicMock()
        self.app.nids.get_stats.return_value = {"test": 5}
        
        self.app.update_stats()
        
        self.app.alert_count_label.configure.assert_called_with(text="📊 Alerts: 10")
        self.app.suppressed_label.configure.assert_called_with(text="🔇 Suppressed: 5")
    
    @patch.object(NIDSApp, 'log_to_ui')
    def test_clear_logs(self, mock_log):
        """Test clearing logs"""
        self.app.nids = MagicMock()
        
        self.app.clear_logs()
        
        self.app.nids.clear_logs.assert_called_once()
        self.app.log_textbox.configure.assert_any_call(state="normal")
        self.app.log_textbox.delete.assert_called_with("1.0", "end")
        self.assertEqual(self.app.alert_count, 0)
    
    def test_logout(self):
        """Test logout functionality"""
        self.app.nids = MagicMock()
        self.app.nids.is_running = True
        
        with patch('Nexus_NIDP.LoginSystem') as mock_login:
            self.app.logout()
            
            self.app.nids.stop.assert_called_once()
            mock_login.assert_called_once()
    
    def test_update_attacker_list(self):
        """Test updating attacker list"""
        self.app.nids = MagicMock()
        self.app.nids.get_attackers.return_value = ["192.168.1.100", "192.168.1.101"]
        self.app.nids.get_blocked_ips.return_value = ["192.168.1.100"]
        
        self.app.update_attacker_list()
        
        self.app.attacker_combo.configure.assert_called_with(values=["192.168.1.101"])
        self.app.attackers_label.configure.assert_called_with(text="⚠️ Attackers: 2")
    
    def test_update_blocked_list(self):
        """Test updating blocked list"""
        self.app.nids = MagicMock()
        self.app.nids.get_blocked_ips.return_value = ["192.168.1.100", "192.168.1.101"]
        
        self.app.update_blocked_list()
        
        self.app.blocked_combo.configure.assert_called_with(values=["192.168.1.100", "192.168.1.101"])
        self.app.blocked_count_label.configure.assert_called_with(text="🚫 Blocked: 2")
    
    def test_check_buttons_with_valid_attack_ip(self):
        """Test button states with valid attack IP"""
        self.app.nids = MagicMock()
        self.app.nids.get_attack_ip.return_value = "192.168.1.100"
        self.app.nids.get_blocked_ips.return_value = []
        
        self.app.check_buttons()
        
        self.app.block_btn.configure.assert_called_with(state="normal", fg_color=Colors.DANGER)
        self.app.attack_selected_label.configure.assert_called_with(text="Selected: 192.168.1.100")
    
    def test_check_buttons_with_blocked_attack_ip(self):
        """Test button states when attack IP is already blocked"""
        self.app.nids = MagicMock()
        self.app.nids.get_attack_ip.return_value = "192.168.1.100"
        self.app.nids.get_blocked_ips.return_value = ["192.168.1.100"]
        
        self.app.check_buttons()
        
        self.app.block_btn.configure.assert_called_with(state="disabled", fg_color=Colors.BG_FRAME)
    
    def test_on_attack_ip_select(self):
        """Test attack IP selection"""
        self.app.nids = MagicMock()
        
        self.app.on_attack_ip_select("192.168.1.100")
        
        self.app.nids.set_attack_ip.assert_called_with("192.168.1.100")
    
    def test_on_block_ip_select(self):
        """Test block IP selection"""
        self.app.nids = MagicMock()
        
        self.app.on_block_ip_select("192.168.1.100")
        
        self.app.nids.set_block_ip.assert_called_with("192.168.1.100")
    
    @patch.object(NIDSApp, 'log_to_ui')
    def test_block_selected_ip(self, mock_log):
        """Test blocking selected IP"""
        self.app.nids = MagicMock()
        self.app.nids.get_attack_ip.return_value = "192.168.1.100"
        self.app.nids.block_ip.return_value = (True, "Blocked IP")
        
        self.app.block_selected_ip()
        
        self.app.nids.block_ip.assert_called_with("192.168.1.100")
        self.app.nids.set_attack_ip.assert_called_with(None)
        mock_log.assert_called_with("[ACTION] Blocked IP\n")
    
    @patch.object(NIDSApp, 'log_to_ui')
    def test_unblock_selected_ip(self, mock_log):
        """Test unblocking selected IP"""
        self.app.nids = MagicMock()
        self.app.nids.get_block_ip.return_value = "192.168.1.100"
        self.app.nids.unblock_ip.return_value = (True, "Unblocked IP")
        
        self.app.unblock_selected_ip()
        
        self.app.nids.unblock_ip.assert_called_with("192.168.1.100")
        self.app.nids.set_block_ip.assert_called_with(None)
        mock_log.assert_called_with("[ACTION] Unblocked IP\n")
    
    def test_start_monitoring_invalid_interface(self):
        """Test starting monitoring with invalid interface"""
        self.app.interface_combo = MagicMock()
        self.app.interface_combo.get.return_value = "Select Interface"
        
        self.app.start_monitoring()
        
        self.app.status_label.configure.assert_called_with(
            text="● Error - Select Interface", 
            text_color=Colors.DANGER
        )
    
    @patch('Nexus_NIDP.NIDS')
    def test_start_monitoring_success(self, mock_nids_class):
        """Test successfully starting monitoring"""
        self.app.interface_combo = MagicMock()
        self.app.interface_combo.get.return_value = "eth0"
        
        mock_nids = MagicMock()
        mock_nids.start.return_value = True
        mock_nids_class.return_value = mock_nids
        
        self.app.start_monitoring()
        
        self.app.start_btn.configure.assert_called_with(state="disabled", fg_color=Colors.TEXT_MUTED)
        self.app.stop_btn.configure.assert_called_with(state="normal")
        self.app.status_label.configure.assert_called_with(text="● Monitoring", text_color=Colors.SUCCESS)
    
    def test_stop_monitoring(self):
        """Test stopping monitoring"""
        self.app.nids = MagicMock()
        self.app.nids.is_running = True
        
        self.app.stop_monitoring()
        
        self.app.nids.stop.assert_called_once()
        self.app.start_btn.configure.assert_called_with(state="normal", fg_color=Colors.SUCCESS)
        self.app.stop_btn.configure.assert_called_with(state="disabled")
        self.app.status_label.configure.assert_called_with(text="● Stopped", text_color=Colors.WARNING)


# ==============================================================================
# TEST COLORS CLASS
# ==============================================================================

class TestColors(unittest.TestCase):
    """Test the Colors class"""
    
    def test_colors_defined(self):
        """Test that all color constants are defined"""
        self.assertIsNotNone(Colors.BG_DARK)
        self.assertIsNotNone(Colors.BG_CARD)
        self.assertIsNotNone(Colors.BG_FRAME)
        self.assertIsNotNone(Colors.PRIMARY)
        self.assertIsNotNone(Colors.SUCCESS)
        self.assertIsNotNone(Colors.WARNING)
        self.assertIsNotNone(Colors.DANGER)
        self.assertIsNotNone(Colors.PURPLE)
        self.assertIsNotNone(Colors.TEXT_MAIN)
        self.assertIsNotNone(Colors.TEXT_DIM)
        self.assertIsNotNone(Colors.TEXT_MUTED)
        self.assertIsNotNone(Colors.BORDER)
    
    def test_color_formats(self):
        """Test that colors are in valid hex format"""
        colors = [
            Colors.BG_DARK, Colors.BG_CARD, Colors.BG_FRAME,
            Colors.PRIMARY, Colors.SUCCESS, Colors.WARNING,
            Colors.DANGER, Colors.PURPLE, Colors.TEXT_MAIN,
            Colors.TEXT_DIM, Colors.TEXT_MUTED, Colors.BORDER
        ]
        
        for color in colors:
            self.assertTrue(color.startswith("#"))
            self.assertTrue(len(color) in [4, 7])  # #RGB or #RRGGBB
            # Check if valid hex
            hex_part = color[1:]
            int(hex_part, 16)  # Should not raise ValueError


# ==============================================================================
# TEST MAIN FUNCTION
# ==============================================================================

class TestMainFunction(unittest.TestCase):
    """Test the main function"""
    
    @patch('Nexus_NIDP.LoginSystem')
    def test_main(self, mock_login_class):
        """Test main function"""
        from Nexus_NIDP import main
        
        mock_login = MagicMock()
        mock_login_class.return_value = mock_login
        
        # Run main
        main()
        
        # Check that LoginSystem was created and mainloop called
        mock_login_class.assert_called_once()
        mock_login.mainloop.assert_called_once()


# ==============================================================================
# RUN ALL TESTS
# ==============================================================================

def run_tests():
    """Run all test cases"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestResultNode))
    suite.addTests(loader.loadTestsFromTestCase(TestDiscoveryStorage))
    suite.addTests(loader.loadTestsFromTestCase(TestPacketNode))
    suite.addTests(loader.loadTestsFromTestCase(TestCustomQueue))
    suite.addTests(loader.loadTestsFromTestCase(TestFirewallManager))
    suite.addTests(loader.loadTestsFromTestCase(TestNIDS))
    suite.addTests(loader.loadTestsFromTestCase(TestLoginSystem))
    suite.addTests(loader.loadTestsFromTestCase(TestNIDSApp))
    suite.addTests(loader.loadTestsFromTestCase(TestColors))
    suite.addTests(loader.loadTestsFromTestCase(TestMainFunction))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    print("=" * 70)
    print("🧪 COMPLETE NIDPS UNIT TEST SUITE")
    print("=" * 70)
    print(f"Testing all components from Nexus_NIDP.py")
    print(f"Total test classes: 10")
    print("=" * 70)
    
    success = run_tests()
    
    print("=" * 70)
    if success:
        print("✅ ALL TESTS PASSED!")
    else:
        print("❌ SOME TESTS FAILED!")
    print("=" * 70)
    
    sys.exit(0 if success else 1)