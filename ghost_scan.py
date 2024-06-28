import os
import time
import threading
from scapy.all import ARP, Ether, srp

# Function to draw an animated ASCII ghost
def draw_ghost(stop_event):
    frames = [
        """
            .-.
           (o o)
           | O |
           |   |
          '~~~~~'
        """,
        """
             .-.
           (o o)
           | O |
           |   |
          '~~~~~'
        """,
        """
              .-.
           (o o)
           | O |
           |   |
          '~~~~~'
        """
    ]

    while not stop_event.is_set():
        for frame in frames:
            if stop_event.is_set():
                break
            os.system('cls' if os.name == 'nt' else 'clear')  # For Windows, use 'cls'; for Linux/OS X, use 'clear'
            print(frame)
            time.sleep(0.2)

# Function to perform network scanning
def network_scan(ip_range):
    print(f"Starting network scan on {ip_range}...")
    
    # Create ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send packet and get response
    result = srp(packet, timeout=2, verbose=False)[0]

    # Parse results
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

# Main function
def main():
    # Start the ghost animation in a separate thread
    stop_event = threading.Event()
    ghost_thread = threading.Thread(target=draw_ghost, args=(stop_event,))
    ghost_thread.daemon = True  # This ensures the ghost animation stops when the main program exits
    ghost_thread.start()

    # Stop the ghost animation after 5 seconds
    time.sleep(5)
    stop_event.set()
    ghost_thread.join()

    # Clear the screen and ask for IP range
    os.system('cls' if os.name == 'nt' else 'clear')
    ip_range = input("Enter the IP range for the network scan (e.g., 192.168.1.0/24): ")

    # Perform the network scan
    devices = network_scan(ip_range)

    # Show the scan results
    print("Network scan completed. Found devices:")
    print("IP" + " " * 18 + "MAC")
    print("-" * 40)
    for device in devices:
        print("{:16}    {}".format(device['ip'], device['mac']))

if __name__ == "__main__":
    main()
