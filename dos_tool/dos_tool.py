import subprocess
import sys

# Cool Banner (ASCII art)
print("""
██████╗  ██████╗ ███████╗    ████████╗ ██████╗  ██████╗ ██╗     
██╔══██╗██╔═══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
██║  ██║██║   ██║███████╗       ██║   ██║   ██║██║   ██║██║     
██║  ██║██║   ██║╚════██║       ██║   ██║   ██║██║   ██║██║     
██████╔╝╚██████╔╝███████║       ██║   ╚██████╔╝╚██████╔╝███████╗
╚═════╝  ╚═════╝ ╚══════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
""")



print("Welcome to DoS Tool! Type a command to run an attack:")
print(" - type 'http' to run slowloris attack")
print(" - type 'syn' to run TCP SYN Flood")
print(" - type 'udp' to run UDP Flood")
print(" - type 'exit' to quit")

while True:
    try:
        choice = input("> ").strip()
        
        if choice == "http":
            host_ip = input("Enter host IP (e.g., 192.168.100.22): ")
            print("Running HTTP Flood...")
            subprocess.run(["python3", "slowloris_attack.py", host_ip])
        elif choice == "syn":
            host_ip = input("Enter host IP (e.g., 192.168.100.22): ")
            print("Running TCP SYN Flood...")
            subprocess.run(["python3", "tcp_syn_attack.py", host_ip])
        elif choice == "udp":
            host_ip = input("Enter host IP (e.g., 192.168.100.22): ")
            print("Running UDP Flood...")
            subprocess.run(["python3", "udp_attack.py", host_ip])
        elif choice == "exit":
            print("Bye!")
            sys.exit(0)
        else:
            print("Wrong input. Try 'http', 'syn', 'udp', or 'exit'.")
    except KeyboardInterrupt:
        print("\nprogram terminated by user")
        sys.exit(0)

    
    