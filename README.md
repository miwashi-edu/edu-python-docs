# edu-python-docs

## Usage

```bash
./scan -p 1-10000 | ./probe | ./report -s "Automatic port scanning"
```


## Prepare

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

## Probe Ports (simple probing of port)

```bash
cd ~
cd ws
cd python-docs
echo '#!'"$(which python3)" >  probe
chmod +x probe
cat >> probe << 'EOF'
import nmap
import sys
import argparse
import re
import os


def is_valid_socket(socket):
    # Regular expression to validate IP:Port or localhost:Port
    pattern = re.compile(r"^(localhost|\d{1,3}(\.\d{1,3}){3}):\d+$")
    return pattern.match(socket)


def probe_socket(socket):
    if not is_valid_socket(socket):
        print(f"Invalid socket format: {socket}", file=sys.stderr)
        return

    nm = nmap.PortScanner()
    ip, port = socket.split(":")
    try:
        nm.scan(ip, port, arguments="-sV")  # -sV for service/version detection
        service_info = "No service detected or port is closed"
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = list(nm[host][proto].keys())
                for port in lport:
                    state = nm[host][proto][port]['state']
                    if state == "open":
                        service = nm[host][proto][port].get('name', 'unknown service')
                        product = nm[host][proto][port].get('product', '')
                        version = nm[host][proto][port].get('version', '')
                        extra = nm[host][proto][port].get('extrainfo', '')
                        service_info = f"{service} {product} {version} {extra}".strip()
                    else:
                        service_info = "Port is closed"
        print(f"{ip}:{port} - {service_info}")
    except Exception as e:
        print(f"Error scanning {socket}: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Probe sockets to identify listening services")
    parser.add_argument("-s", "--socket", nargs="?", help="Single socket to probe in format IP:Port or localhost:Port")
    args = parser.parse_args()

    if args.socket:
        probe_socket(args.socket)
    elif not os.isatty(sys.stdin.fileno()):
        # Handling piped input
        for line in sys.stdin:
            socket = line.strip()
            if socket and is_valid_socket(socket):
                probe_socket(socket)
    else:
        print("No valid socket provided and not receiving piped input. Exiting.", file=sys.stderr)


if __name__ == "__main__":
    main()
EOF
```

## report (report result of port scanning)

```bash

cd ~
cd ws
cd python-docs
echo '#!'"$(which python3)" >  report
chmod +x report
cat >> report << 'EOF'
#!/usr/bin/env python3
import argparse
from docx import Document
from datetime import datetime
import sys


def find_or_create_section(document, section_title):
    """
    Find the paragraph object for a section title or create a new section if not found.
    """
    for paragraph in document.paragraphs:
        if paragraph.text == section_title and paragraph.style == document.styles['Heading 1']:
            return paragraph
    # If section not found, add it at the end of the document
    return document.add_heading(section_title, level=1)


def append_to_section(doc_path, section_title, content):
    try:
        doc = Document(doc_path)
    except Exception:
        doc = Document()
        doc.add_heading(f"Penetration Testing {datetime.now().strftime('%Y-%m-%d')}", 0)

    section_paragraph = find_or_create_section(doc, section_title)

    # Insert the content after the section title
    doc.add_paragraph(content)
    doc.save(doc_path)


def main():
    parser = argparse.ArgumentParser(description="Generate a report from findings")
    parser.add_argument("-o", "--output", help="Output document name (default: pentest-<current date>.docx)")
    parser.add_argument("-s", "--section", default="Untitled", help="Section name under which to append findings (default: Untitled)")
    args = parser.parse_args()

    output_file = args.output if args.output else f"pentest-{datetime.now().strftime('%Y-%m-%d')}.docx"

    if not sys.stdin.isatty():
        # Handling piped input
        for line in sys.stdin:
            finding = line.strip()
            if finding:
                append_to_section(output_file, args.section, finding)
                print(f"Appended finding to section '{args.section}' in {output_file}", file=sys.stderr)
    else:
        # Handling direct input
        print("Enter your finding (Ctrl+D to finish):", file=sys.stderr)
        while True:
            try:
                line = input()
                finding = line.strip()
                if finding:
                    append_to_section(output_file, args.section, finding)
                    print(f"Appended finding to section '{args.section}' in {output_file}", file=sys.stderr)
            except EOFError:
                break


if __name__ == "__main__":
    main()
EOF
```

## sinfo (system information, add configuration of system performing penetration test)

```bash
cd ~
cd ws
cd python-docs
echo '#!'"$(which python3)" >  sinfo
chmod +x sinfo
cat >> sinfo << 'EOF'
#!/usr/bin/env python3
import argparse
from docx import Document
from datetime import datetime
import platform
import socket
import os


def get_system_info():
    """Gather system meta information."""
    info = {
        "Operating System": platform.system(),
        "OS Version": platform.version(),
        "OS Release": platform.release(),
        "Architecture": platform.machine(),
        "Hostname": socket.gethostname(),
        "IP Address": socket.gethostbyname(socket.gethostname())
    }
    return info


def add_info_to_doc(doc_path, info):
    """Add system information to the specified section in the document."""
    doc = Document(doc_path)

    # Find or add the section title
    section_title = "System Information"
    section_found = False
    for paragraph in doc.paragraphs:
        if paragraph.text == section_title:
            section_found = True
            break
    if not section_found:
        doc.add_heading(section_title, level=1)

    # Add system information
    for key, value in info.items():
        doc.add_paragraph(f"{key}: {value}")

    doc.save(doc_path)


def main():
    parser = argparse.ArgumentParser(description="Add system information to a pentest report")
    parser.add_argument("-o", "--output", help="Output document name (default: pentest-<current date>.docx)")
    args = parser.parse_args()

    output_date = datetime.now().strftime('%Y-%m-%d')
    output_file = args.output if args.output else f"pentest-{output_date}.docx"

    # Add system information to the document
    system_info = get_system_info()
    add_info_to_doc(output_file, system_info)
    print(f"System information added to {output_file}")


if __name__ == "__main__":
    main()
EOF
```

## disclaimer (add a disclaimer to the report)

```bash
cd ~
cd ws
cd python-docs
echo '#!'"$(which python3)" >  disclaimer
chmod +x disclaimer
cat >> disclaimer << 'EOF'
#!/usr/bin/env python3
import argparse
from docx import Document
from datetime import datetime
import sys


def add_disclaimer_section(doc_path, disclaimer_text):
    """Add a disclaimer section to the document."""
    try:
        doc = Document(doc_path)
    except FileNotFoundError:
        doc = Document()
        doc.add_heading('Disclaimer', level=1)
    else:
        doc.add_page_break()  # Add a page break before the disclaimer for readability
        doc.add_heading('Disclaimer', level=1)

    doc.add_paragraph(disclaimer_text)
    doc.save(doc_path)


def main():
    parser = argparse.ArgumentParser(description="Add a disclaimer section to the pentest report")
    parser.add_argument("-o", "--output", help="Output document name (default: pentest-<current date>.docx)", default=f"pentest-{datetime.now().strftime('%Y-%m-%d')}.docx")
    args = parser.parse_args()

    # Disclaimer text (customize as needed)
    disclaimer_text = "The findings in this report are for authorized use only. The methodologies used are intended for educational purposes and should not be used maliciously."

    add_disclaimer_section(args.output, disclaimer_text)
    print(f"Disclaimer section added to '{args.output}'.", file=sys.stderr)


if __name__ == "__main__":
    main()
EOF
```

## intro (add an intro section to report)

```bash
cd ~
cd ws
cd python-docs
echo '#!'"$(which python3)" >  intro
chmod +x intro
cat >> intro << 'EOF'
#!/usr/bin/env python3
import argparse
from docx import Document
from datetime import datetime
import sys
import os


def add_or_update_intro_section(doc, intro_text):
    """Add or update the Introduction section."""
    # Search for the Introduction heading
    intro_heading_found = False
    for paragraph in doc.paragraphs:
        if paragraph.text == "Introduction" and paragraph.style.name == 'Heading 1':
            intro_heading_found = True
            # Clear existing introduction content
            while paragraph._element.getnext() is not None:
                next_elem = paragraph._element.getnext()
                if next_elem.tag.endswith('heading'):
                    break
                paragraph._element.getparent().remove(next_elem)
            break

    if not intro_heading_found:
        # Add Introduction as the second section
        doc.add_paragraph("Introduction", style='Heading 1')

    # Add the introduction text
    doc.add_paragraph(intro_text)


def main():
    parser = argparse.ArgumentParser(description="Add or update an Introduction section in the pentest report")
    parser.add_argument("-o", "--output", help="Output document name (default: pentest-<current date>.docx)",
                        default=f"pentest-{datetime.now().strftime('%Y-%m-%d')}.docx")
    args = parser.parse_args()

    # Check if the document exists, create a new one if not
    if os.path.exists(args.output):
        doc = Document(args.output)
    else:
        doc = Document()
        doc.add_heading(f'Penetration Testing {datetime.now().strftime("%Y-%m-%d")}', 0)  # Default title

    intro_text = "This document provides an overview of the penetration testing methodology, scope, and objectives."
    add_or_update_intro_section(doc, intro_text)
    doc.save(args.output)
    print(f"Introduction section added/updated in '{args.output}'.", file=sys.stderr)


if __name__ == "__main__":
    main()
EOF
```

## client (add client info to document)

```bash
cd ~
cd ws
cd python-docs
echo '#!'"$(which python3)" >  client
chmod +x client
cat >> client << 'EOF'
#!/usr/bin/env python3
import argparse
from docx import Document
from datetime import datetime
import sys
import os


def update_document_title(doc, title_text):
    """Update the document title if it exists, or add a new title."""
    title_updated = False
    for paragraph in doc.paragraphs:
        if paragraph.style.name == 'Title':
            paragraph.text = title_text
            title_updated = True
            break

    # If no title paragraph with 'Title' style was found, add a new title at the beginning of the document.
    if not title_updated:
        doc.add_paragraph(title_text, style='Title')


def add_custom_header(doc_path, client_name):
    """Add or update the document title with custom information."""
    title_text = f"Penetration Testing {datetime.now().strftime('%Y-%m-%d')} - Client: {client_name}"

    # Check if the document exists to decide on opening or creating a new one.
    if os.path.exists(doc_path):
        doc = Document(doc_path)
    else:
        doc = Document()

    update_document_title(doc, title_text)
    doc.save(doc_path)


def main():
    parser = argparse.ArgumentParser(description="Update document with custom client title")
    parser.add_argument("-o", "--output", help="Output document name (default: pentest-<current date>.docx)", default=f"pentest-{datetime.now().strftime('%Y-%m-%d')}.docx")
    parser.add_argument("client", help="Client name to include in the document title")
    args = parser.parse_args()

    add_custom_header(args.output, args.client)
    print(f"Document '{args.output}' updated with custom client title.", file=sys.stderr)


if __name__ == "__main__":
    main()
EOF
```

## pinfo (port info)

```bash
cd ~
cd ws
cd python-docs
echo '#!'"$(which python3)" >  pinfo
chmod +x pinfo
cat >> pinfo << 'EOF'
#!/usr/bin/env python3
import argparse
from docx import Document
from datetime import datetime
import sys
import os

def add_or_update_default_ports_section(doc):
    """Add or update the 'Default Ports' section with a table of standard ports."""
    section_title = "Default Ports"
    # Standard ports and their services
    ports_services = [
        (22, "SSH"),
        (25, "SMTP"),
        (53, "DNS"),
        (80, "HTTP"),
        (443, "HTTPS"),
    ]

    # Attempt to find the Default Ports section
    section_found = False
    for paragraph in doc.paragraphs:
        if paragraph.text == section_title and paragraph.style.name == 'Heading 1':
            section_found = True
            break

    # If section is found, clear existing table if present
    if section_found:
        for table in doc.tables:
            # Assuming the table follows the section immediately
            p_index = doc.element.body.index(paragraph._element)
            t_index = doc.element.body.index(table._element)
            if t_index > p_index:
                doc.element.body.remove(table._element)
                break

    # If section not found, add it
    if not section_found:
        doc.add_paragraph(section_title, style='Heading 1')

    # Add or update the table
    table = doc.add_table(rows=1, cols=2)
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'Port'
    hdr_cells[1].text = 'Service'
    for port, service in ports_services:
        row_cells = table.add_row().cells
        row_cells[0].text = str(port)
        row_cells[1].text = service

def main():
    parser = argparse.ArgumentParser(description="Update or create a document with a 'Default Ports' section")
    parser.add_argument("-o", "--output", help="Output document name (default: pentest-<current date>.docx)", default=f"pentest-{datetime.now().strftime('%Y-%m-%d')}.docx")
    args = parser.parse_args()

    # Check if the document exists to decide on opening or creating a new one.
    if os.path.exists(args.output):
        doc = Document(args.output)
    else:
        doc = Document()
        # Add a default title to ensure the document structure.
        doc.add_heading(f'Penetration Testing {datetime.now().strftime("%Y-%m-%d")}', 0)

    add_or_update_default_ports_section(doc)
    doc.save(args.output)
    print(f"Document '{args.output}' updated with 'Default Ports' section.", file=sys.stderr)

if __name__ == "__main__":
    main()
EOF
```
