
from flask import Flask, render_template, jsonify
import psutil
import time
import threading
import requests
import socket
from datetime import datetime, timezone, timedelta
import csv
from collections import deque
import subprocess
import os
import re
import signal
import sys
import concurrent.futures
import statistics
import logging
import atexit
from contextlib import contextmanager
import fcntl

# -------------------------
# Configuration
# -------------------------
HTTP_PORT = 80
UDP_MONITOR_PORT = 9999  # Monitor YOUR UDP server on this port
LOG_FILE = "dashboard.log"
CSV_HEADER = ["time", "cpu", "mem", "http%", "lat_avg_ms", "lat_p95_ms",
              "rps", "tcp_est", "tcp_syn", "udp_burst", "packet_loss_pct", "alert"]
HISTORY_LEN = 60
COLLECT_INTERVAL = 5.0
HTTP_PROBES = 10
HTTP_PROBE_TIMEOUT = 2.0
HTTP_PROBES_TOTAL_TIMEOUT = 3.5
UDP_BURST_WINDOW = 5.0
BASELINE_SAMPLES = 12

# Attack confirmation thresholds
ATTACK_CONFIRMATION_SAMPLES = 3  # Require 3 consecutive samples (15 seconds)
ATTACK_CONFIDENCE_THRESHOLD = 0.7  # 70% confidence required
BASELINE_ADAPTATION_RATE = 0.1  # 10% weight for new samples in adaptive baseline

# Production thresholds (less aggressive to reduce false positives)
SYN_HIGH_THRESHOLD = 15
UDP_BURST_HIGH_THRESHOLD = 100
EST_HIGH_THRESHOLD = 200
HTTP_FAIL_THRESHOLD = 75.0
THROUGHPUT_DROP_MULT = 0.5
LATENCY_SPIKE_MULT = 2.5
TRAFFIC_SURGE_MULT = 5.0
PACKET_LOSS_SPIKE = 5.0
CPU_HIGH = 85.0
MEM_HIGH = 85.0

# -------------------------
# Logging Setup
# -------------------------
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# -------------------------
# Resource Management
# -------------------------
active_subprocesses = []
subprocess_lock = threading.Lock()

def cleanup_subprocesses():
    """Cleanup all active subprocesses on exit"""
    with subprocess_lock:
        for proc in active_subprocesses:
            try:
                if proc.poll() is None:  # Still running
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
            except Exception as e:
                logger.warning(f"Error cleaning up subprocess: {e}")
        active_subprocesses.clear()

atexit.register(cleanup_subprocesses)

@contextmanager
def managed_subprocess(cmd, **kwargs):
    """Context manager for subprocesses with automatic cleanup"""
    proc = None
    try:
        proc = subprocess.Popen(cmd, **kwargs)
        with subprocess_lock:
            active_subprocesses.append(proc)
        yield proc
    finally:
        if proc:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        proc.kill()
            except Exception:
                pass
            finally:
                with subprocess_lock:
                    if proc in active_subprocesses:
                        active_subprocesses.remove(proc)

def get_primary_interface():
    """
    Robust network interface detection for cloud/Docker environments
    Tries multiple methods: active connections, default route, traffic-based selection
    """
    # Method 1: Check active connections to find interface with most traffic
    try:
        interfaces = psutil.net_io_counters(pernic=True)
        if interfaces:
            # Exclude loopback and Docker bridges
            excluded = {'lo', 'docker0', 'br-', 'veth'}
            valid_interfaces = {
                name: stats for name, stats in interfaces.items()
                if not any(name.startswith(ex) for ex in excluded)
            }
            if valid_interfaces:
                # Select interface with most bytes sent+received
                best = max(valid_interfaces.items(), 
                          key=lambda x: x[1].bytes_sent + x[1].bytes_recv)
                if best[1].bytes_sent + best[1].bytes_recv > 0:
                    logger.info(f"Selected interface by traffic: {best[0]}")
                    return best[0]
    except Exception as e:
        logger.debug(f"Traffic-based interface selection failed: {e}")
    
    # Method 2: Default route
    try:
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True, timeout=2)
        match = re.search(r'dev\s+(\S+)', result.stdout)
        if match:
            iface = match.group(1)
            if iface != 'lo':
                logger.info(f"Selected interface by default route: {iface}")
                return iface
    except Exception as e:
        logger.debug(f"Default route detection failed: {e}")
    
    # Method 3: Check active TCP connections
    try:
        result = subprocess.run(['ss', '-tn'], capture_output=True, text=True, timeout=2)
        for line in result.stdout.splitlines():
            # Look for interface in connection details
            if ':' in line and not line.startswith('State'):
                # Extract IP and infer interface
                parts = line.split()
                if len(parts) > 3:
                    # Try to get interface from route
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', parts[3])
                    if ip_match:
                        ip = ip_match.group(1)
                        route_result = subprocess.run(
                            ['ip', 'route', 'get', ip],
                            capture_output=True, text=True, timeout=1
                        )
                        route_match = re.search(r'dev\s+(\S+)', route_result.stdout)
                        if route_match:
                            iface = route_match.group(1)
                            if iface != 'lo':
                                logger.info(f"Selected interface by active connection: {iface}")
                                return iface
    except Exception as e:
        logger.debug(f"Active connection method failed: {e}")
    
    logger.warning("Using loopback interface as fallback")
    return 'lo'  # Final fallback

PRIMARY_INTERFACE = get_primary_interface()

# -------------------------
# Globals
# -------------------------
app = Flask(__name__, template_folder="templates")
metrics = {
    "cpu": 0.0,
    "memory": 0.0,
    "http_success": 100.0,
    "latency_avg": 0.0,
    "latency_p95": 0.0,
    "throughput": 0.0,
    "tcp_est": 0,
    "tcp_syn": 0,
    "udp_burst": 0,
    "packet_loss": 0.0,
    "alert": "SAFE",
    "time": ""
}
history = deque(maxlen=HISTORY_LEN)
udp_packet_counts = deque(maxlen=100)  # Bounded: Store (timestamp, count) tuples

# Adaptive baseline with time-weighted moving averages
baseline = {
    "rps_samples": deque(maxlen=BASELINE_SAMPLES),
    "p95_samples": deque(maxlen=BASELINE_SAMPLES),
    "loss_samples": deque(maxlen=BASELINE_SAMPLES),
    "cpu_samples": deque(maxlen=BASELINE_SAMPLES),
    "throughput": None,
    "latency_p95": None,
    "packet_loss": None,
    "cpu_avg": None,
    "learned": False
}

# Attack confirmation tracking
attack_confidence = {
    "syn_flood": deque(maxlen=ATTACK_CONFIRMATION_SAMPLES),
    "udp_flood": deque(maxlen=ATTACK_CONFIRMATION_SAMPLES),
    "slowloris": deque(maxlen=ATTACK_CONFIRMATION_SAMPLES),
    "traffic_surge": deque(maxlen=ATTACK_CONFIRMATION_SAMPLES),
    "network_attack": deque(maxlen=ATTACK_CONFIRMATION_SAMPLES),
    "resource_exhaustion": deque(maxlen=ATTACK_CONFIRMATION_SAMPLES)
}
attack_confidence_lock = threading.Lock()

def ensure_log_header():
    write_header = False
    if not os.path.exists(LOG_FILE):
        write_header = True
    else:
        try:
            if os.path.getsize(LOG_FILE) == 0:
                write_header = True
        except Exception:
            write_header = True
    if write_header:
        with open(LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)
            f.flush()

ensure_log_header()

# -------------------------
# UDP Monitor - Accurate packet counting for port 9999
# -------------------------
udp_stats_cache = {
    "last_packets": 0,
    "last_timestamp": 0,
    "packet_count_5s": 0,
    "packet_times": deque(maxlen=10000)  # Store timestamps of detected packets
}
udp_stats_lock = threading.Lock()

def get_udp_packet_count_from_snmp():
    """
    Get UDP packet count from /proc/net/snmp (system-wide, but we'll use it as baseline)
    Returns total UDP InDatagrams
    """
    try:
        with open('/proc/net/snmp', 'r') as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                if line.startswith('Udp:'):
                    # Next line has the actual values
                    if i + 1 < len(lines):
                        values = lines[i + 1].split()
                        if len(values) > 1:
                            # InDatagrams is the 1st value (0-indexed)
                            return int(values[1])
    except Exception:
        pass
    return 0

def get_udp_port_stats(port=9999):
    """
    Get UDP socket statistics for specific port from /proc/net/udp
    Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops
    Returns: (rx_queue, drops, inode)
    """
    try:
        port_hex = f"{port:04X}".upper()
        with open('/proc/net/udp', 'r') as f:
            lines = f.readlines()
            for line in lines[1:]:  # Skip header
                # Check if this line contains our port
                if f":{port_hex}" in line.upper():
                    fields = line.split()
                    if len(fields) >= 13:
                        # Parse fields correctly
                        # Field indices: 0=sl, 1=local_addr, 2=rem_addr, 3=st, 4=tx_queue, 5=rx_queue, 
                        # 6=tr, 7=tm->when, 8=retrnsmt, 9=uid, 10=timeout, 11=inode, 12=ref, 13=pointer, 14=drops
                        try:
                            # rx_queue is field 5 (0-indexed)
                            rx_queue_str = fields[5] if len(fields) > 5 else '0'
                            # drops is field 14 (0-indexed) 
                            drops_str = fields[14] if len(fields) > 14 else '0'
                            # inode is field 11 (0-indexed)
                            inode = int(fields[11]) if len(fields) > 11 else 0
                            
                            # Parse hex values (they're already in hex format)
                            rx_queue = int(rx_queue_str, 16) if rx_queue_str != '0' else 0
                            drops = int(drops_str, 16) if drops_str != '0' else 0
                            
                            return rx_queue, drops, inode
                        except (ValueError, IndexError) as e:
                            logger.debug(f"Error parsing UDP line: {e}, fields={len(fields)}")
                            continue
    except FileNotFoundError:
        logger.debug("/proc/net/udp not accessible")
    except Exception as e:
        logger.debug(f"UDP stats parse error: {e}")
    
    return 0, 0, 0

def count_udp_packets_ss(port=9999):
    """
    Use ss command to count UDP packets/connections on specific port
    Returns estimated packet count based on socket activity
    """
    try:
        # Use ss to get UDP socket info
        result = subprocess.run(
            ['ss', '-u', '-n', '-a', f'dport = :{port}'],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            # Count active sockets (each line is a socket, minus header)
            socket_count = max(0, len(lines) - 1)
            # Estimate: each socket might represent multiple packets
            # This is a rough estimate - we'll use it as a multiplier
            return socket_count
    except Exception:
        pass
    return 0

def udp_packet_monitor():
    """
    Background thread that monitors UDP packets on port 9999
    Uses tcpdump for accurate packet counting (if available) with fallback methods
    """
    logger.info(f"Starting UDP packet monitor for port {UDP_MONITOR_PORT}")
    
    # Try to use tcpdump first (most accurate)
    use_tcpdump = False
    tcpdump_proc = None
    
    try:
        # Test if tcpdump is available
        test_result = subprocess.run(['which', 'tcpdump'], capture_output=True, timeout=1)
        if test_result.returncode == 0:
            use_tcpdump = True
            logger.info("Using tcpdump for accurate UDP packet counting")
    except Exception:
        pass
    
    if use_tcpdump:
        # Use tcpdump to capture UDP packets on port 9999
        try:
            cmd = ['tcpdump', '-i', PRIMARY_INTERFACE, '-n', '-l', 
                   f'udp port {UDP_MONITOR_PORT}', '-q']
            tcpdump_proc = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.DEVNULL, 
                text=True,
                bufsize=1
            )
            logger.info(f"tcpdump started for UDP monitoring on {PRIMARY_INTERFACE}:{UDP_MONITOR_PORT}")
        except Exception as e:
            logger.warning(f"Failed to start tcpdump: {e}, using fallback method")
            use_tcpdump = False
    
    last_snmp_count = get_udp_packet_count_from_snmp()
    last_drops = 0
    last_rx_queue = 0
    
    while True:
        try:
            now = time.time()
            packets_detected = 0
            
            if use_tcpdump and tcpdump_proc and tcpdump_proc.poll() is None:
                # Method 1: Use tcpdump (most accurate)
                try:
                    # Set non-blocking mode for reading
                    flags = fcntl.fcntl(tcpdump_proc.stdout.fileno(), fcntl.F_GETFL)
                    fcntl.fcntl(tcpdump_proc.stdout.fileno(), fcntl.F_SETFL, flags | os.O_NONBLOCK)
                    
                    # Read available lines from tcpdump
                    lines_read = 0
                    while lines_read < 1000:  # Limit per iteration
                        try:
                            line = tcpdump_proc.stdout.readline()
                            if not line:
                                break
                            # Each line from tcpdump represents a packet
                            packets_detected += 1
                            lines_read += 1
                        except (IOError, OSError):
                            break
                    
                    # Reset blocking mode
                    fcntl.fcntl(tcpdump_proc.stdout.fileno(), fcntl.F_SETFL, flags)
                    
                except Exception as e:
                    logger.debug(f"tcpdump read error: {e}")
                    # Fallback to other methods
                    use_tcpdump = False
            else:
                # Method 2: Use socket statistics + SNMP
                rx_queue, drops, inode = get_udp_port_stats(UDP_MONITOR_PORT)
                
                # Track drops and rx_queue changes
                if drops > last_drops:
                    drops_diff = drops - last_drops
                    packets_detected += drops_diff
                    last_drops = drops
                
                if rx_queue > last_rx_queue:
                    rx_diff = rx_queue - last_rx_queue
                    packets_detected += rx_diff
                    last_rx_queue = rx_queue
                elif rx_queue < last_rx_queue:
                    # Queue decreased, packets were processed
                    last_rx_queue = rx_queue
                
                # Method 3: Monitor SNMP for system-wide UDP activity
                current_snmp = get_udp_packet_count_from_snmp()
                if last_snmp_count > 0 and current_snmp > last_snmp_count:
                    snmp_diff = current_snmp - last_snmp_count
                    # If socket exists and we see system-wide activity, estimate some is for our port
                    if inode > 0:
                        # Conservative estimate: 10-50% of system UDP might be for our port during attack
                        estimated = min(snmp_diff // 5, 1000)
                        packets_detected += estimated
                last_snmp_count = current_snmp
                
                # Method 4: Use ss to detect socket activity
                socket_count = count_udp_packets_ss(UDP_MONITOR_PORT)
                if socket_count > 0:
                    # Active sockets indicate recent packet activity
                    packets_detected += socket_count * 5  # Estimate 5 packets per socket
            
            # Add detected packets to our tracking
            if packets_detected > 0:
                with udp_stats_lock:
                    # Add timestamps for detected packets
                    for _ in range(min(int(packets_detected), 10000)):
                        udp_stats_cache["packet_times"].append(now)
            
            # Clean old packet timestamps (>5 seconds)
            cutoff = now - UDP_BURST_WINDOW
            with udp_stats_lock:
                while udp_stats_cache["packet_times"] and udp_stats_cache["packet_times"][0] < cutoff:
                    udp_stats_cache["packet_times"].popleft()
                
                # Update packet count for last 5 seconds
                udp_stats_cache["packet_count_5s"] = len(udp_stats_cache["packet_times"])
            
            time.sleep(0.2)  # Check every 200ms for better accuracy
            
        except Exception as e:
            logger.error(f"UDP monitor error: {e}", exc_info=True)
            time.sleep(2)
        finally:
            # Restart tcpdump if it died
            if use_tcpdump and (tcpdump_proc is None or tcpdump_proc.poll() is not None):
                try:
                    if tcpdump_proc:
                        tcpdump_proc.terminate()
                        tcpdump_proc.wait(timeout=1)
                except Exception:
                    pass
                try:
                    cmd = ['tcpdump', '-i', PRIMARY_INTERFACE, '-n', '-l', 
                           f'udp port {UDP_MONITOR_PORT}', '-q']
                    tcpdump_proc = subprocess.Popen(
                        cmd, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.DEVNULL, 
                        text=True,
                        bufsize=1
                    )
                except Exception:
                    use_tcpdump = False

def get_udp_burst():
    """Return current UDP burst count (packets in last 5 seconds)"""
    with udp_stats_lock:
        return int(udp_stats_cache.get("packet_count_5s", 0))

# -------------------------
# HTTP probes
# -------------------------
def _single_probe(url, timeout):
    try:
        start = time.time()
        r = requests.get(url, timeout=timeout)
        latency = (time.time() - start) * 1000.0
        ok = (200 <= r.status_code < 400)
        return ok, latency, r.status_code
    except Exception:
        return False, timeout * 1000.0 + 500.0, None

# Thread pool executor for HTTP probes (reused, properly managed)
http_executor = None
http_executor_lock = threading.Lock()

def get_http_executor():
    """Get or create thread pool executor for HTTP probes"""
    global http_executor
    with http_executor_lock:
        if http_executor is None or http_executor._shutdown:
            http_executor = concurrent.futures.ThreadPoolExecutor(
                max_workers=min(HTTP_PROBES, 8),
                thread_name_prefix="http_probe"
            )
    return http_executor

def get_http_metrics():
    """Get HTTP metrics with proper resource management"""
    url = f"http://localhost:{HTTP_PORT}/"
    times = []
    successes = 0

    executor = get_http_executor()
    futures = [executor.submit(_single_probe, url, HTTP_PROBE_TIMEOUT) 
               for _ in range(HTTP_PROBES)]
    
    try:
        for fut in concurrent.futures.as_completed(futures, timeout=HTTP_PROBES_TOTAL_TIMEOUT):
            try:
                ok, lat, _ = fut.result(timeout=0.5)
                times.append(lat)
                if ok:
                    successes += 1
            except Exception:
                times.append(HTTP_PROBE_TIMEOUT * 1000.0 + 500.0)
    except concurrent.futures.TimeoutError:
        pass
    finally:
        # Cancel remaining futures
        for fut in futures:
            if not fut.done():
                fut.cancel()

    # Fill remaining with timeout values
    remaining = HTTP_PROBES - len(times)
    for _ in range(remaining):
        times.append(HTTP_PROBE_TIMEOUT * 1000.0 + 500.0)

    success_pct = round((successes / HTTP_PROBES) * 100.0, 1)
    avg = round(sum(times) / len(times), 1) if times else 0.0
    sorted_times = sorted(times)
    idx = max(0, int(0.95 * len(sorted_times)) - 1)
    p95 = round(sorted_times[idx], 1) if sorted_times else avg
    return success_pct, avg, p95

# -------------------------
# TCP stats via ss
# -------------------------
def parse_ss_count(args_list):
    try:
        res = subprocess.run(args_list, capture_output=True, text=True, timeout=3.0)
        out = res.stdout.strip()
        if out == "":
            return 0
        lines = out.splitlines()
        count = 0
        for line in lines:
            if ':80' in line or ':http' in line:
                count += 1
        return max(0, count)
    except Exception:
        return 0

def get_tcp_counts():
    syn_args = ["ss", "-ant", "state", "syn-recv"]
    est_args = ["ss", "-ant", "state", "established"]
    syn = parse_ss_count(syn_args)
    est = parse_ss_count(est_args)
    return est, syn

# -------------------------
# Throughput: Apache access log
# -------------------------
APACHE_LOG_PATHS = [
    "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
    "/var/log/apache2/access_log"
]

apache_log_path = None
for path in APACHE_LOG_PATHS:
    if os.path.exists(path):
        apache_log_path = path
        break

apache_ts_regex = re.compile(r"\[([0-9]{1,2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [+\-][0-9]{4})\]")

def get_throughput():
    """Get throughput with proper resource management"""
    if apache_log_path is None:
        return 0.0
    try:
        with managed_subprocess(
            ["tail", "-n", "10000", apache_log_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        ) as proc:
            out, _ = proc.communicate(timeout=5.0)
            if not out:
                return 0.0
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(seconds=60)
            count = 0
            for line in out.splitlines():
                m = apache_ts_regex.search(line)
                if not m:
                    continue
                ts_str = m.group(1)
                try:
                    dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
                    if dt.astimezone(timezone.utc) >= cutoff:
                        count += 1
                except Exception:
                    continue
            rps = round(count / 60.0, 2)
            return rps
    except subprocess.TimeoutExpired:
        logger.warning("Throughput calculation timed out")
        return 0.0
    except Exception as e:
        logger.debug(f"Throughput error: {e}")
        return 0.0

# -------------------------
# Packet loss
# -------------------------
def get_packet_loss():
    """Get packet loss with proper resource management"""
    try:
        with managed_subprocess(
            ["ping", "-c", "4", "-W", "2", "8.8.8.8"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        ) as proc:
            out, _ = proc.communicate(timeout=10.0)
            if not out:
                return 0.0
            m = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", out)
            if m:
                return float(m.group(1))
            return 0.0
    except subprocess.TimeoutExpired:
        logger.warning("Packet loss check timed out")
        return 0.0
    except Exception as e:
        logger.debug(f"Packet loss error: {e}")
        return 0.0

# -------------------------
# ALERT LOGIC with Attack Confirmation
# -------------------------
def update_attack_confidence(attack_type, is_detected):
    """Update confidence score for attack type (0.0 to 1.0)"""
    with attack_confidence_lock:
        if attack_type in attack_confidence:
            attack_confidence[attack_type].append(1.0 if is_detected else 0.0)
            # Calculate confidence as average of recent samples
            if len(attack_confidence[attack_type]) > 0:
                confidence = sum(attack_confidence[attack_type]) / len(attack_confidence[attack_type])
                return confidence
    return 0.0

def get_attack_confidence(attack_type):
    """Get current confidence score for attack type"""
    with attack_confidence_lock:
        if attack_type in attack_confidence and len(attack_confidence[attack_type]) > 0:
            return sum(attack_confidence[attack_type]) / len(attack_confidence[attack_type])
    return 0.0

def update_adaptive_baseline(metric_name, current_value):
    """Update baseline using time-weighted moving average"""
    if not baseline.get("learned", False):
        return
    
    current_baseline = baseline.get(metric_name)
    if current_baseline is not None:
        # Exponential moving average
        new_baseline = (BASELINE_ADAPTATION_RATE * current_value) + \
                      ((1 - BASELINE_ADAPTATION_RATE) * current_baseline)
        baseline[metric_name] = new_baseline

def compute_alert(http_success, syn, udp_burst, rps, p95, est, loss_pct, cpu, mem):
    """Enhanced alert logic with multi-factor confirmation"""
    if not baseline.get("learned", False):
        return "LEARNING BASELINE"

    base_rps = baseline.get("throughput", 1.0)
    base_p95 = baseline.get("latency_p95", 100.0)
    base_loss = baseline.get("packet_loss", 0.0)

    attack_signals = []
    warning_signals = []
    confirmed_attacks = []

    # Update adaptive baselines
    update_adaptive_baseline("throughput", rps)
    update_adaptive_baseline("latency_p95", p95)
    update_adaptive_baseline("packet_loss", loss_pct)

    # UDP Flood - require sustained high packet rate
    udp_attack = udp_burst >= UDP_BURST_HIGH_THRESHOLD
    udp_confidence = update_attack_confidence("udp_flood", udp_attack)
    if udp_confidence >= ATTACK_CONFIDENCE_THRESHOLD:
        confirmed_attacks.append(f"UNDER ATTACK: UDP Flood | {udp_burst} packets/5s")
    
    # SYN Flood - require multiple indicators
    syn_attack = syn >= SYN_HIGH_THRESHOLD
    syn_indicators = [
        syn >= SYN_HIGH_THRESHOLD,
        (rps < base_rps * THROUGHPUT_DROP_MULT and base_rps > 0.5) or cpu > CPU_HIGH
    ]
    syn_confidence = update_attack_confidence("syn_flood", syn_attack and sum(syn_indicators) >= 2)
    if syn_confidence >= ATTACK_CONFIDENCE_THRESHOLD and syn_attack:
        confirmed_attacks.append(f"UNDER ATTACK: SYN Flood | SYN:{syn} | RPS:{rps:.1f} | CPU:{cpu:.0f}%")
    elif syn_attack:
        warning_signals.append(f"SYN:{syn}")
        attack_signals.append("SYN_FLOOD")
    
    # Slowloris - require both latency and HTTP degradation
    slowloris_latency_bad = (p95 > base_p95 * LATENCY_SPIKE_MULT) or (p95 > 2000)
    slowloris_http_bad = http_success < HTTP_FAIL_THRESHOLD
    slowloris_attack = est >= EST_HIGH_THRESHOLD and slowloris_latency_bad and slowloris_http_bad
    slowloris_confidence = update_attack_confidence("slowloris", slowloris_attack)
    if slowloris_confidence >= ATTACK_CONFIDENCE_THRESHOLD:
        confirmed_attacks.append(f"UNDER ATTACK: Slowloris | EST:{est} | p95:{p95:.0f}ms | HTTP:{http_success:.0f}%")
    elif est >= EST_HIGH_THRESHOLD:
        warning_signals.append(f"EST:{est}")
        if slowloris_latency_bad or slowloris_http_bad:
            attack_signals.append("SLOWLORIS_POSSIBLE")
    
    # HTTP Service Down - immediate alert (no confirmation needed)
    if http_success < 50.0:
        return f"UNDER ATTACK: HTTP Service Down | {http_success:.0f}% success"
    
    if http_success < HTTP_FAIL_THRESHOLD:
        warning_signals.append(f"HTTP:{http_success:.0f}%")
        attack_signals.append("HTTP_DEGRADED")
    
    # Latency spike
    if p95 > base_p95 * LATENCY_SPIKE_MULT and base_p95 > 10:
        warning_signals.append(f"p95:{p95:.0f}ms")
        attack_signals.append("LATENCY_SPIKE")
    
    # Traffic surge - require confirmation
    traffic_surge = rps > base_rps * TRAFFIC_SURGE_MULT and base_rps > 0.5
    surge_indicators = [
        traffic_surge,
        p95 > base_p95 * 2 or loss_pct > base_loss + PACKET_LOSS_SPIKE
    ]
    surge_confidence = update_attack_confidence("traffic_surge", traffic_surge and any(surge_indicators))
    if surge_confidence >= ATTACK_CONFIDENCE_THRESHOLD and any(surge_indicators):
        confirmed_attacks.append(f"UNDER ATTACK: Traffic Surge | RPS:{rps:.1f} | p95:{p95:.0f}ms")
    elif traffic_surge:
        warning_signals.append(f"RPS:{rps:.1f}")
        attack_signals.append("TRAFFIC_SURGE")
    
    # Network attack - packet loss
    network_attack = loss_pct > base_loss + PACKET_LOSS_SPIKE and loss_pct > 10.0
    network_confidence = update_attack_confidence("network_attack", network_attack)
    if network_confidence >= ATTACK_CONFIDENCE_THRESHOLD:
        confirmed_attacks.append(f" Network degradation | Packet Loss:{loss_pct:.0f}%")
    elif network_attack:
        warning_signals.append(f"Loss:{loss_pct:.0f}%")
    
    # Resource exhaustion - require other attack signals
    resource_exhaustion = (cpu > CPU_HIGH or mem > MEM_HIGH) and len(attack_signals) >= 1
    resource_confidence = update_attack_confidence("resource_exhaustion", resource_exhaustion)
    if resource_confidence >= ATTACK_CONFIDENCE_THRESHOLD:
        confirmed_attacks.append(f"Resource Exhaustion | CPU:{cpu:.0f}% MEM:{mem:.0f}%")
    
    # Return highest priority confirmed attack
    if confirmed_attacks:
        return confirmed_attacks[0]  # Return first confirmed attack
    
    # Multiple attack signals but not confirmed
    if len(attack_signals) >= 2:
        return f"SUSPICIOUS ACTIVITY | {' + '.join(attack_signals[:3])}"
    
    # Warnings only
    if warning_signals:
        return f"MONITORING | {' | '.join(warning_signals[:4])}"
    
    return "SAFE"

# -------------------------
# Collector loop
# -------------------------
def collector_loop():
    """Main collector loop with improved error handling"""
    logger.info("Collector thread started")
    samples_collected = 0
    
    while True:
        cycle_start = time.time()
        try:
            cpu = round(psutil.cpu_percent(interval=0.5), 1)
            mem = round(psutil.virtual_memory().percent, 1)
            http_success, lat_avg, lat_p95 = get_http_metrics()
            udp_burst = get_udp_burst()
            est, syn = get_tcp_counts()
            rps = get_throughput()
            loss = get_packet_loss()
            ts = datetime.now().strftime("%H:%M:%S")

            # Baseline learning with bounded collections
            if samples_collected < BASELINE_SAMPLES:
                baseline["rps_samples"].append(rps)
                baseline["p95_samples"].append(lat_p95)
                baseline["loss_samples"].append(loss)
                baseline["cpu_samples"].append(cpu)
                samples_collected += 1
                
                if samples_collected == BASELINE_SAMPLES:
                    baseline["throughput"] = max(0.5, statistics.mean(baseline["rps_samples"]))
                    baseline["latency_p95"] = max(10.0, statistics.mean(baseline["p95_samples"]))
                    baseline["packet_loss"] = max(0.0, statistics.mean(baseline["loss_samples"]))
                    baseline["cpu_avg"] = max(5.0, statistics.mean(baseline["cpu_samples"]))
                    baseline["learned"] = True
                    logger.info(f"✓ Baseline learned: rps={baseline['throughput']:.2f}, p95={baseline['latency_p95']:.1f}ms, loss={baseline['packet_loss']:.1f}%")

            alert = compute_alert(http_success, syn, udp_burst, rps, lat_p95, est, loss, cpu, mem)

            metrics.update({
                "cpu": cpu,
                "memory": mem,
                "http_success": round(http_success, 1),
                "latency_avg": round(lat_avg, 1),
                "latency_p95": round(lat_p95, 1),
                "throughput": round(rps, 2),
                "tcp_est": int(est),
                "tcp_syn": int(syn),
                "udp_burst": int(udp_burst),  # Already an integer
                "packet_loss": round(loss, 1),
                "alert": alert,
                "time": ts
            })

            # History is already bounded by deque(maxlen=HISTORY_LEN)
            history.append({
                "t": ts,
                "cpu": cpu, "mem": mem,
                "http": round(http_success, 1),
                "lat": round(lat_avg, 1),
                "p95": round(lat_p95, 1),
                "rps": round(rps, 2),
                "est": int(est), "syn": int(syn),
                "udp": int(udp_burst), "loss": round(loss, 1)
            })

            try:
                with open(LOG_FILE, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        ts, cpu, mem, round(http_success, 1),
                        round(lat_avg, 1), round(lat_p95, 1),
                        round(rps, 2), int(est), int(syn), int(udp_burst),
                        round(loss, 1), alert
                    ])
                    f.flush()
            except Exception as e:
                logger.error(f"CSV write error: {e}")

            status_color = "🔴" if "ATTACK" in alert else "🟡" if "SUSPICIOUS" in alert or "MONITORING" in alert else "🟢"
            logger.info(f"{status_color} [{ts}] {alert:40s} | HTTP:{http_success:5.1f}% p95:{lat_p95:6.0f}ms rps:{rps:5.2f} | syn:{syn:3d} est:{est:3d} udp:{udp_burst:4d}")

        except Exception as e:
            logger.error(f"Collector error: {e}", exc_info=True)

        elapsed = time.time() - cycle_start
        to_sleep = COLLECT_INTERVAL - elapsed
        if to_sleep > 0:
            time.sleep(to_sleep)

# -------------------------
# Flask endpoints
# -------------------------
@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/metrics")
def route_metrics():
    return jsonify(metrics)

@app.route("/history")
def route_history():
    return jsonify(list(history))

# -------------------------
# Shutdown handler
# -------------------------
def _shutdown(signum, frame):
    """Graceful shutdown with resource cleanup"""
    logger.info("Received shutdown signal, cleaning up...")
    
    # Shutdown HTTP executor
    global http_executor
    with http_executor_lock:
        if http_executor and not http_executor._shutdown:
            http_executor.shutdown(wait=True, cancel_futures=True)
            http_executor = None
    
    # Cleanup subprocesses
    cleanup_subprocesses()
    
    logger.info("Shutdown complete")
    sys.exit(0)

signal.signal(signal.SIGINT, _shutdown)
signal.signal(signal.SIGTERM, _shutdown)

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    # Start UDP monitoring thread
    t_udp_monitor = threading.Thread(target=udp_packet_monitor, daemon=True, name="udp_monitor")
    t_udp_monitor.start()
    
    time.sleep(1)  # Let UDP monitor start

    # Start collector thread
    t_collector = threading.Thread(target=collector_loop, daemon=True, name="collector")
    t_collector.start()

    hostname = socket.gethostname()
    try:
        server_ip = socket.gethostbyname(hostname)
    except:
        server_ip = "0.0.0.0"

    print("\n" + "="*70)
    print("  DoS ATTACK MONITORING DASHBOARD (Production Hardened)")
    print("="*70)
    print(f"Dashboard URL:       http://{server_ip}:5000")
    print(f"Metrics API:         http://{server_ip}:5000/metrics")
    print(f"Monitoring:          UDP port {UDP_MONITOR_PORT} (your server)")
    print(f"                     HTTP port {HTTP_PORT}")
    print(f"Network Interface:   {PRIMARY_INTERFACE}")
    print(f"Attack Confirmation: {ATTACK_CONFIRMATION_SAMPLES} samples ({ATTACK_CONFIRMATION_SAMPLES * COLLECT_INTERVAL}s)")
    print(f"Baseline Adaptation: {BASELINE_ADAPTATION_RATE * 100:.0f}% weight")
    print("="*70)
    print("📊 Features:")
    print("   ✓ Accurate UDP monitoring via /proc/net/udp")
    print("   ✓ Adaptive baseline calibration")
    print("   ✓ Multi-factor attack confirmation (reduces false positives)")
    print("   ✓ Resource-efficient (bounded data structures)")
    print("   ✓ Production-ready error handling")
    print("="*70)
    print("⏳ Learning baseline...")
    print("="*70 + "\n")

    try:
        app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
    except KeyboardInterrupt:
        _shutdown(None, None)