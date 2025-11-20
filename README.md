# DoS Attack and Mitigation Lab

A modular, virtualized environment for studying Denial-of-Service (DoS) attacks and evaluating defensive techniques.  
The project includes attack scripts, mitigation automation, real-time monitoring, and target services that simulate real-world behavior under load.

This lab is designed for learning, experimentation, and demonstrating practical cybersecurity skills.

---

## Features

### Attack Modules
Implementation of commonly studied DoS techniques:
- Slowloris (HTTP connection exhaustion)
- TCP SYN Flood (half-open connection saturation)
- UDP Flood (high-volume stateless traffic)

Each script includes logging, adjustable intensity, and controlled execution to keep experiments safe and reproducible.

### Mitigation Toolkit
A unified shell script that equips the environment with:
- IP blocking and unblocking
- Traffic rate limiting rules
- SYN cookies enable/disable controls
- Live status inspection for all defenses
- Rule cleanup and reset functions

The toolkit is focused on clarity and reliability, helping users understand how defense layers interact.

### Monitoring Dashboard
A Flask-based dashboard for observing:
- CPU and memory usage
- Request success and failure patterns
- Latency under varying loads
- TCP connection states
- Traffic spikes during attack execution
- Service uptime and responsiveness

This provides visibility into how attacks manifest and how mitigation changes system behavior.

### Target Services
To provide consistent, testable scenarios:
- Apache HTTP server configuration
- Lightweight Python UDP server

Both servers act as realistic test targets for attack scripts and dashboard analytics.

---

## Project Structure

attacks/
- slowloris.py
- tcp_syn_flood.py
- udp_flood.py

defense/
- mitigation.sh

dashboard/
- app.py
- templates/

servers/
- udp_server.py

README.md


---

## How It Works

1. Target services run inside a virtual machine.  
2. Attack modules generate controlled stress on the services.  
3. The dashboard collects live system metrics and displays them.  
4. The mitigation script can be triggered at any point to apply protections.  
5. Changes in system behavior can be observed before, during, and after defense activation.

This forms a complete test cycle for understanding DoS behavior and response strategies.

---

## Usage

### Running an Attack
Each attack script accepts parameters for tuning speed, duration, and concurrency.  
Example:
python3 slowloris.py <target_ip> 



### Applying Mitigation
sudo bash mitigation.sh

makefile
Copy code
Available actions include enabling defenses, disabling rules, checking status, and flushing configurations.

### Launching the Dashboard
python3 app.py


Opens the monitoring interface for observing attack behavior.

---

## Experiments and Evaluation

The environment supports:
- Baseline system performance measurements
- Behavior observation under Slowloris, SYN flood, and UDP flood
- Measurement of latency, failure rates, and connection states
- Analysis of how mitigation affects service recovery
- Understanding kernel protections such as SYN cookies

This makes it useful for reports, coursework, and security research.

---

## Intended Use

This project is designed strictly for:
- Academic study
- Security learning
- Controlled lab experiments
- Demonstrations for coursework or portfolios

All testing must be performed inside isolated machines or private network.

---

## Skills Demonstrated

### Network Security
- Understanding of common DoS attack vectors
- Practical implementation of Slowloris, TCP SYN Flood, and UDP Flood
- Hands-on firewall configuration using iptables
- Experience with SYN cookies and kernel-level protections
- Ability to analyze network behavior under stress

### System Administration
- Linux server setup and hardening
- Apache HTTP server configuration for testing
- Managing processes, services, and resource monitoring
- Controlled execution of high-load scenarios inside virtual machines

### Defensive Engineering
- Designing automated mitigation scripts
- Implementing IP blocking, rate limiting, and rule cleanup
- Monitoring and validating system recovery after attack
- Evaluating effectiveness of layered defense strategies

### Backend Development
- Developing a Flask-based monitoring dashboard
- Collecting real-time system metrics (CPU, memory, connection states)
- Building update-ready views using templates and dynamic data
- Managing background collectors for performance tracking

### Python Programming
- Building threaded and asynchronous attack scripts
- Designing safe, parameterized traffic generators
- Implementing socket programming for TCP and UDP
- Writing readable, structured, and testable code

### Bash Scripting
- Automating firewall operations with safe execution flows
- Creating interactive menus, status checks, and rule handlers
- Logging results for analysis and debugging

### System Monitoring and Analysis
- Tracking latency, throughput, failure rates, and traffic bursts
- Measuring the effect of mitigation in real time
- Identifying attack signatures through observable patterns
- Understanding TCP connection states and system load behavior

---

## Credits

Developed as a practical learning environment for studying network security, attack behavior, and defensive mechanisms.
