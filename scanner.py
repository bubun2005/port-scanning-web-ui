#!/usr/bin/env python3
import socket
import struct
import time
import ipaddress
import threading
import json
import csv
from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Dict, Optional, Union
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Constants
DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 100
MAX_PORT = 65535

class ScanType(Enum):
    TCP_CONNECT = auto()
    SYN = auto()
    UDP = auto()
    PING = auto()

@dataclass
class PortResult:
    port: int
    is_open: bool
    service: Optional[str] = None
    banner: Optional[str] = None
    scan_type: Optional[ScanType] = None

@dataclass
class HostResult:
    ip: str
    is_alive: bool
    ports: List[PortResult]
    hostname: Optional[str] = None

class PortScanner:
    def __init__(self, timeout: float = DEFAULT_TIMEOUT, max_threads: int = DEFAULT_THREADS):
        self.timeout = timeout
        self.max_threads = max_threads
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Alt"
        }
    
    def resolve_hostname(self, ip: str) -> Optional[str]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def tcp_connect_scan(self, ip: str, port: int) -> PortResult:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                
                # Try to grab banner if port is open
                banner = None
                try:
                    s.send(b"GET / HTTP/1.1\r\n\r\n")
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass
                
                service = self.common_ports.get(port)
                return PortResult(port=port, is_open=True, service=service, banner=banner, scan_type=ScanType.TCP_CONNECT)
        except (socket.timeout, ConnectionRefusedError, socket.error):
            return PortResult(port=port, is_open=False, scan_type=ScanType.TCP_CONNECT)
    
    def syn_scan(self, ip: str, port: int) -> PortResult:
        try:
            # Create raw socket (requires root privileges)
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.settimeout(self.timeout)
            
            # Set IP headers manually
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Craft SYN packet
            packet = self._build_syn_packet(ip, port)
            s.sendto(packet, (ip, 0))
            
            # Listen for response
            while True:
                response = s.recvfrom(1024)[0]
                if self._is_syn_ack_response(response, port):
                    s.close()
                    return PortResult(port=port, is_open=True, service=self.common_ports.get(port), scan_type=ScanType.SYN)
        except (socket.timeout, PermissionError, socket.error):
            return PortResult(port=port, is_open=False, scan_type=ScanType.SYN)
        finally:
            s.close()
    
    def _build_syn_packet(self, dst_ip: str, dst_port: int) -> bytes:
        # IP header
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # kernel will fill this
        ip_id = 54321
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0  # kernel will fill this
        ip_saddr = socket.inet_aton("0.0.0.0")  # spoofed source
        ip_daddr = socket.inet_aton(dst_ip)
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               ip_ihl_ver, ip_tos, ip_tot_len,
                               ip_id, ip_frag_off, ip_ttl, ip_proto,
                               ip_check, ip_saddr, ip_daddr)
        
        # TCP header
        tcp_source = 54321  # random source port
        tcp_dest = dst_port
        tcp_seq = 0
        tcp_ack_seq = 0
        tcp_doff = 5  # data offset
        tcp_fin = 0
        tcp_syn = 1
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        tcp_window = socket.htons(5840)
        tcp_check = 0
        tcp_urg_ptr = 0
        
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
        
        tcp_header = struct.pack('!HHLLBBHHH',
                                 tcp_source, tcp_dest, tcp_seq,
                                 tcp_ack_seq, tcp_offset_res, tcp_flags,
                                 tcp_window, tcp_check, tcp_urg_ptr)
        
        # Pseudo header for checksum
        source_address = socket.inet_aton("0.0.0.0")
        dest_address = socket.inet_aton(dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        
        psh = struct.pack('!4s4sBBH',
                          source_address, dest_address,
                          placeholder, protocol, tcp_length)
        psh = psh + tcp_header
        
        tcp_check = self._checksum(psh)
        
        # Repack with correct checksum
        tcp_header = struct.pack('!HHLLBBHHH',
                                 tcp_source, tcp_dest, tcp_seq,
                                 tcp_ack_seq, tcp_offset_res, tcp_flags,
                                 tcp_window, tcp_check, tcp_urg_ptr)
        
        return ip_header + tcp_header
    
    def _is_syn_ack_response(self, packet: bytes, port: int) -> bool:
        # Parse IP header
        ip_header = packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        # Get TCP header
        tcp_header_start = iph[0] & 0xF * 4
        tcp_header = packet[tcp_header_start:tcp_header_start+20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
        
        # Check if this is a SYN-ACK response to our port
        source_port = tcph[0]
        dest_port = tcph[1]
        flags = tcph[5]
        syn_flag = (flags & 0x02) >> 1
        ack_flag = (flags & 0x10) >> 4
        
        return syn_flag == 1 and ack_flag == 1 and source_port == port
    
    def _checksum(self, data: bytes) -> int:
        if len(data) % 2 != 0:
            data += b'\0'
        
        res = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i+1]
            res = res + w
        
        res = (res >> 16) + (res & 0xFFFF)
        res = ~res & 0xFFFF
        return res
    
    def udp_scan(self, ip: str, port: int) -> PortResult:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(b'', (ip, port))
                s.recvfrom(1024)
                return PortResult(port=port, is_open=True, service=self.common_ports.get(port), scan_type=ScanType.UDP)
        except socket.timeout:
            # Might be open (UDP is connectionless)
            return PortResult(port=port, is_open=None, service=self.common_ports.get(port), scan_type=ScanType.UDP)
        except (ConnectionRefusedError, socket.error):
            return PortResult(port=port, is_open=False, scan_type=ScanType.UDP)
    
    def ping_sweep(self, ip: str) -> bool:
        try:
            # ICMP ping (requires root on Linux)
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.settimeout(self.timeout)
            
            # Create ICMP packet
            packet = self._build_icmp_packet()
            s.sendto(packet, (ip, 0))
            
            # Wait for response
            s.recvfrom(1024)
            s.close()
            return True
        except (socket.timeout, PermissionError, socket.error):
            return False
    
    def _build_icmp_packet(self) -> bytes:
        # ICMP header
        icmp_type = 8  # ICMP Echo Request
        icmp_code = 0
        icmp_checksum = 0
        icmp_id = 12345
        icmp_seq = 1
        
        # Dummy payload
        payload = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        
        # Pack header
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        
        # Calculate checksum
        icmp_checksum = self._checksum(header + payload)
        
        # Repack with correct checksum
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        
        return header + payload
    
    def scan_ports(self, ip: str, ports: Union[List[int], str], scan_type: ScanType = ScanType.TCP_CONNECT) -> HostResult:
        if isinstance(ports, str):
            if ports == 'all':
                ports = list(range(1, MAX_PORT + 1))
            elif ports == 'common':
                ports = list(self.common_ports.keys())
            else:
                raise ValueError("Invalid port range specified")
        
        open_ports = []
        hostname = self.resolve_hostname(ip)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for port in ports:
                if scan_type == ScanType.TCP_CONNECT:
                    future = executor.submit(self.tcp_connect_scan, ip, port)
                elif scan_type == ScanType.SYN:
                    future = executor.submit(self.syn_scan, ip, port)
                elif scan_type == ScanType.UDP:
                    future = executor.submit(self.udp_scan, ip, port)
                else:
                    raise ValueError("Invalid scan type")
                
                futures.append(future)
            
            for future in as_completed(futures):
                result = future.result()
                if result.is_open:
                    open_ports.append(result)
        
        return HostResult(ip=ip, is_alive=len(open_ports) > 0, ports=open_ports, hostname=hostname)
    
    def scan_network(self, network: str, ports: Union[List[int], str], scan_type: ScanType = ScanType.TCP_CONNECT) -> List[HostResult]:
        hosts = []
        network = ipaddress.ip_network(network, strict=False)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for ip in network.hosts():
                ip_str = str(ip)
                future = executor.submit(self._scan_host, ip_str, ports, scan_type)
                futures.append(future)
            
            for future in as_completed(futures):
                result = future.result()
                if result.is_alive:
                    hosts.append(result)
        
        return hosts
    
    def _scan_host(self, ip: str, ports: Union[List[int], str], scan_type: ScanType) -> HostResult:
        # First check if host is alive
        is_alive = self.ping_sweep(ip)
        
        if not is_alive:
            return HostResult(ip=ip, is_alive=False, ports=[])
        
        # If host is alive, scan ports
        return self.scan_ports(ip, ports, scan_type)
    
    def scan_multiple_hosts(self, hosts: List[str], ports: Union[List[int], str], scan_type: ScanType = ScanType.TCP_CONNECT) -> List[HostResult]:
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self._scan_host, host, ports, scan_type): host for host in hosts}
            
            for future in as_completed(futures):
                results.append(future.result())
        
        return results

class OutputFormatter:
    @staticmethod
    def text(results: Union[HostResult, List[HostResult]], verbose: bool = False) -> str:
        if isinstance(results, HostResult):
            return OutputFormatter._format_single_host_text(results, verbose)
        else:
            return "\n".join(OutputFormatter._format_single_host_text(r, verbose) for r in results)
    
    @staticmethod
    def _format_single_host_text(host: HostResult, verbose: bool) -> str:
        output = []
        hostname = f" ({host.hostname})" if host.hostname else ""
        output.append(f"Host: {host.ip}{hostname} is {'up' if host.is_alive else 'down'}")
        
        if host.is_alive and host.ports:
            output.append("PORT     STATE    SERVICE")
            for port_result in host.ports:
                state = "open" if port_result.is_open else "closed"
                service = port_result.service or "unknown"
                line = f"{port_result.port:<9}{state:<9}{service}"
                if verbose and port_result.banner:
                    line += f"\n  Banner: {port_result.banner}"
                output.append(line)
        
        return "\n".join(output)
    
    @staticmethod
    def json(results: Union[HostResult, List[HostResult]]) -> str:
        if isinstance(results, HostResult):
            return json.dumps(results.__dict__, default=lambda o: o.__dict__, indent=2)
        else:
            return json.dumps([r.__dict__ for r in results], default=lambda o: o.__dict__, indent=2)
    
    @staticmethod
    def csv(results: Union[HostResult, List[HostResult]]) -> str:
        if isinstance(results, HostResult):
            results = [results]
        
        output = []
        writer = csv.writer(output)
        writer.writerow(["Host", "Hostname", "Port", "State", "Service", "Banner"])
        
        for host in results:
            for port in host.ports:
                state = "open" if port.is_open else "closed"
                writer.writerow([
                    host.ip,
                    host.hostname or "",
                    port.port,
                    state,
                    port.service or "",
                    port.banner or ""
                ])
        
        return "\n".join(output)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Professional Port Scanner (Nmap-lite)")
    
    # Target specification
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", help="Single target IP or hostname")
    target_group.add_argument("-n", "--network", help="Network range in CIDR notation (e.g., 192.168.1.0/24)")
    target_group.add_argument("-f", "--file", help="File containing list of targets (one per line)")
    
    # Port specification
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument("-p", "--ports", help="Port or port range (e.g., 80 or 20-100)")
    port_group.add_argument("--common-ports", action="store_true", help="Scan common ports only")
    port_group.add_argument("--all-ports", action="store_true", help="Scan all ports (1-65535)")
    
    # Scan options
    parser.add_argument("-sT", "--tcp-connect", action="store_true", help="TCP Connect scan (default)")
    parser.add_argument("-sS", "--syn-scan", action="store_true", help="SYN stealth scan (requires root)")
    parser.add_argument("-sU", "--udp-scan", action="store_true", help="UDP scan")
    parser.add_argument("-P", "--ping-sweep", action="store_true", help="Ping sweep only")
    
    # Output options
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-oJ", "--output-json", action="store_true", help="Output in JSON format")
    parser.add_argument("-oC", "--output-csv", action="store_true", help="Output in CSV format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    # Performance options
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS, help="Max threads (default: 100)")
    
    return parser.parse_args()

def parse_ports(ports_str: Optional[str], common_ports: bool, all_ports: bool) -> Union[List[int], str]:
    if all_ports:
        return "all"
    if common_ports:
        return "common"
    if not ports_str:
        return "common"  # default to common ports
    
    ports = []
    parts = ports_str.split(",")
    
    for part in parts:
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    
    return ports

def main():
    args = parse_arguments()
    
    # Initialize scanner
    scanner = PortScanner(timeout=args.timeout, max_threads=args.threads)
    
    # Determine scan type
    if args.syn_scan:
        scan_type = ScanType.SYN
    elif args.udp_scan:
        scan_type = ScanType.UDP
    elif args.ping_sweep:
        scan_type = ScanType.PING
    else:
        scan_type = ScanType.TCP_CONNECT  # default
    
    # Parse ports
    ports = parse_ports(args.ports, args.common_ports, args.all_ports)
    
    # Get targets
    targets = []
    if args.target:
        targets = [args.target]
    elif args.network:
        network = ipaddress.ip_network(args.network, strict=False)
        targets = [str(host) for host in network.hosts()]
    elif args.file:
        with open(args.file) as f:
            targets = [line.strip() for line in f if line.strip()]
    
    # Perform scan
    results = []
    if scan_type == ScanType.PING:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scanner.ping_sweep, target): target for target in targets}
            
            for future in as_completed(futures):
                target = futures[future]
                is_alive = future.result()
                results.append(HostResult(ip=target, is_alive=is_alive, ports=[], hostname=scanner.resolve_hostname(target)))
    else:
        results = scanner.scan_multiple_hosts(targets, ports, scan_type)
    
    # Generate output
    if args.output_json:
        output = OutputFormatter.json(results)
    elif args.output_csv:
        output = OutputFormatter.csv(results)
    else:
        output = OutputFormatter.text(results, args.verbose)
    
    # Write output to file or stdout
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
    else:
        print(output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan aborted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)