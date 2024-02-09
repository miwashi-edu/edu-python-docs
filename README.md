# edu-python-docs

## prepare

```bash
cd ~
cd ws
mkdir python-docs && cd python-docs
pip install python-nmap
pip install pymetasploit3
pip install python-docx
```


## Scan Ports

```bash
cd ~
cd ws
cd python-docs
echo '#!'"$(which python3)" >  scan
chmod +x scan
cat >> scan << 'EOF'
import argparse
import socket

def scan_ports(host="127.0.0.1", port_range=(1, 1024), protocol="tcp"):
    open_ports = []
    if protocol.lower() == "tcp":
        for port in range(port_range[0], port_range[1]+1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((host, port))
                    if result == 0:
                        open_ports.append(port)
            except Exception:
                pass
    elif protocol.lower() == "udp":
        for port in range(port_range[0], port_range[1]+1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(1)
                    s.sendto(b'', (host, port))
                    s.recvfrom(1024)
                    open_ports.append(port)
            except socket.timeout:
                pass
            except Exception:
                pass
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="Simple Port Scanner for Piping")
    parser.add_argument("-H", "--host", default="127.0.0.1", help="Host to scan, default is localhost")
    parser.add_argument("-p", "--port", default="1-1024", help="Port range to scan, default is 1-1024")
    parser.add_argument("-t", "--type", default="tcp", choices=["tcp", "udp"], help="Type of scan: tcp or udp, default is tcp")
    args = parser.parse_args()

    host = args.host
    port_range = tuple(map(int, args.port.split('-')))
    protocol = args.type

    if len(port_range) != 2 or port_range[0] >= port_range[1]:
        print("Invalid port range. Please use the format start-end (e.g., 20-80).", file=sys.stderr)
        return

    open_ports = scan_ports(host, port_range, protocol)
    for port in open_ports:
        print(port)

if __name__ == "__main__":
    main()
EOF
```

## Probe Ports

```bash
cd ~
cd ws
cd python-docs
echo '#!'"$(which python3)" >  probe
chmod +x probe
cat >> probe << 'EOF'
import nmap
import argparse
import sys

def probe_socket(socket):
    nm = nmap.PortScanner()
    try:
        ip, port = socket.split(":")
        print(f"Scanning {ip} on port {port}...")
        nm.scan(ip, port, arguments="-sV")  # -sV for service/version detection
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    service = nm[host][proto][port].get('name', 'unknown')
                    product = nm[host][proto][port].get('product', '')
                    version = nm[host][proto][port].get('version', '')
                    extra = nm[host][proto][port].get('extrainfo', '')
                    print(f"{host}:{port} - {service} {product} {version} {extra}")
    except Exception as e:
        print(f"Error scanning {socket}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Probe sockets to identify listening services")
    parser.add_argument("socket", nargs="?", help="Single socket to probe in format IP:Port (optional)")
    args = parser.parse_args()

    if args.socket:
        probe_socket(args.socket)
    else:
        try:
            while True:
                socket = input()
                if ":" in socket:
                    probe_socket(socket)
        except EOFError:
            pass

if __name__ == "__main__":
    main()
EOF
```

## Exploit Ports

```bash
cd ~
cd ws
cd python-docs
echo '#!'"$(which python3)" >  exploit
chmod +x exploit
cat >> exploit << 'EOF'
from pymetasploit3.msfrpc import MsfRpcClient
import argparse
import sys

def run_metasploit_exploit(client, target_ip, target_port, exploit, payload):
    console = client.consoles.console()
    console.write(f"use {exploit}\n")
    console.write(f"set RHOSTS {target_ip}\n")
    console.write(f"set RPORT {target_port}\n")
    if payload:
        console.write(f"set PAYLOAD {payload}\n")
    console.write("exploit\n")
    return console.read()

def main():
    parser = argparse.ArgumentParser(description="Metasploit Aggressive Testing Script")
    parser.add_argument("-p", "--password", required=True, help="Metasploit RPC password")
    parser.add_argument("-e", "--exploit", required=True, help="Metasploit exploit to use")
    parser.add_argument("-l", "--payload", help="Payload to use (optional)")
    parser.add_argument("socket", nargs="?", help="Single socket to process in format IP:Port (optional)")
    args = parser.parse_args()

    client = MsfRpcClient(args.password)

    if args.socket:
        target_ip, target_port = args.socket.split(":")
        result = run_metasploit_exploit(client, target_ip, target_port, args.exploit, args.payload)
        print(f"Results for {args.socket}:\n{result}")
    else:
        try:
            while True:
                socket = input()
                if ":" in socket:
                    target_ip, target_port = socket.split(":")
                    result = run_metasploit_exploit(client, target_ip, target_port, args.exploit, args.payload)
                    print(f"Results for {socket}:\n{result}")
        except EOFError:
            pass

if __name__ == "__main__":
    main()
EOF
```
