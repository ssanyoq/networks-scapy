from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import threading
import time

class IPDefender:
    def __init__(self):
        self.protected_pairs = {}
        self.running = False
        self.sniff_thread = None
        self.defend_thread = None
        self.arp_cache = {}

    def add_protected_pair(self, ip, mac):
        self.protected_pairs[ip] = mac.lower()
        print(f"Added protected pair: {ip} -> {mac}")

    def remove_protected_pair(self, ip):
        if ip in self.protected_pairs:
            del self.protected_pairs[ip]
            print(f"Removed protected pair for IP: {ip}")

    def start(self):
        if self.running:
            print("Already running")
            return
        
        self.running = True
        self.sniff_thread = threading.Thread(target=self._sniff_arp)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        
        self.defend_thread = threading.Thread(target=self._defend_pairs)
        self.defend_thread.daemon = True
        self.defend_thread.start()
        
        print("IPDefender started")

    def stop(self):
        self.running = False
        if self.sniff_thread:
            self.sniff_thread.join()
        if self.defend_thread:
            self.defend_thread.join()
        print("IPDefender stopped")

    def _sniff_arp(self):
        sniff(filter="arp", prn=self._process_arp_packet, store=0, stop_filter=lambda x: not self.running)

    def _process_arp_packet(self, packet):
        if not self.running:
            return
        
        if ARP in packet:
            print(packet[ARP])
            arp = packet[ARP]
            
            if arp.op == 2:  # ARP-ответ
                self.arp_cache[arp.psrc] = arp.hwsrc.lower()
            
            if arp.op == 2 and arp.psrc == arp.pdst and arp.hwdst == "ff:ff:ff:ff:ff:ff":
                ip = arp.psrc
                mac = arp.hwsrc.lower()
                
                if ip in self.protected_pairs and mac != self.protected_pairs[ip]:
                    print(f"Detected Gratuitous ARP spoofing: {ip} claims to be {mac}, but should be {self.protected_pairs[ip]}")
                    self._send_correct_arp(ip)

    def _send_correct_arp(self, ip):
        if ip not in self.protected_pairs:
            return
        
        correct_mac = self.protected_pairs[ip]
        print(f"Sending correct ARP response: {ip} is at {correct_mac}")
        
        arp_response = ARP(
            op=2,
            psrc=ip,
            hwsrc=correct_mac,
            pdst="255.255.255.255",
            hwdst="ff:ff:ff:ff:ff:ff"
        )
        
        send(arp_response, verbose=0)

    def _defend_pairs(self):
        """Периодически отправляет корректные ARP-ответы для защищаемых пар"""
        while self.running:
            for ip, mac in self.protected_pairs.items():
                self._send_correct_arp(ip)
            time.sleep(60) 


if __name__ == "__main__":
    defender = IPDefender()
    
    # defender.add_protected_pair("169.254.23.62", "00:11:22:33:44:55")
    defender.add_protected_pair("169.254.23.62", "50:eb:f6:2e:c8:fb")
    
    try:
        defender.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        defender.stop()
        print("Exiting")
