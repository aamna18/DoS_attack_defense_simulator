import socket

import time

import threading

# CHANGE THIS

IP = "192.168.100.22"   # Linux server IP

PORT = 9999

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

s.settimeout(2)  # wait max 2 sec for reply

print(f"CLIENT → {IP}:{PORT}")

print("Type messages. Empty = stop.")

print("'auto' = auto test every 1 sec\n")

def send_one(msg):

    try:

        s.sendto(msg.encode(), (IP, PORT))

        print(f"→ Sent: {msg}")

        

        reply, _ = s.recvfrom(1024)

        print(f"← Got: {reply.decode()}\n")

        return True

    except socket.timeout:

        print("❌ NO REPLY → Server UNAVAILABLE\n")

        return False

    except:

        print("Error. Try again.\n")

        return False

# Auto mode thread

def auto_test():

    seq = 0

    while True:

        seq += 1

        msg = f"AUTO {seq}"

        send_one(msg)

        time.sleep(1)

# Main input

while True:

    user = input("You: ").strip()

    

    if user == "":

        print("Bye!")

        break

    elif user.lower() == "auto":

        print("Auto mode ON → 1 msg/sec")

        threading.Thread(target=auto_test, daemon=True).start()

        continue

    else:

        send_one(user)

