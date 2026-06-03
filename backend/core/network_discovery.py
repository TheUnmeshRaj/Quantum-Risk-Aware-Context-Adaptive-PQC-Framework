"""
backend/core/network_discovery.py
==================================
Tier 1 network device discovery: ARP scanning for local subnet hosts.

Uses scapy for lightweight ARP pinging to discover active devices
on the local network without requiring nmap or privileged scanning.
"""

import shutil
import socket
import time
from typing import Any, Optional
from urllib.parse import urlparse

try:
    from scapy.all import ARP, Ether, srp  # type: ignore
except ImportError:
    ARP = None

try:
    import nmap  # type: ignore
except ImportError:
    nmap = None

try:
    from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf  # type: ignore
except ImportError:
    ServiceBrowser = None
    ServiceInfo = None
    Zeroconf = None

from backend.utils.logger import get_logger

logger = get_logger(__name__)


def get_local_subnet(iface: Optional[str] = None) -> Optional[str]:
    """
    Infer local subnet from the default interface.
    Returns CIDR like '192.168.1.0/24' or None if detection fails.
    """
    try:
        # Get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Convert to /24 subnet
        parts = local_ip.split(".")
        return f"{'.'.join(parts[:3])}.0/24"
    except Exception as e:
        logger.warning("Could not auto-detect subnet: %s", e)
        return None


def scan_arp(subnet: str = "192.168.1.0/24", timeout: int = 2) -> list[dict]:
    """
    Perform lightweight ARP scan on given subnet.
    
    Returns list of dicts with keys: ip, mac, hostname (best-effort)
    """
    if ARP is None:
        logger.error("scapy not installed; cannot perform ARP scan")
        return []

    devices = []
    
    try:
        logger.info(f"Starting ARP scan on {subnet}...")
        
        # Craft ARP requests
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        
        # Send and receive
        result = srp(packet, timeout=timeout, verbose=False)
        
        for sent, received in result[0]:
            ip = received.psrc
            mac = received.hwsrc
            
            # Try hostname resolution (non-blocking, best effort)
            hostname = "unknown"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.timeout):
                pass
            
            devices.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
            })
            logger.debug(f"Found: {ip} ({mac}) — {hostname}")
        
        logger.info(f"ARP scan complete: {len(devices)} devices found")
    except Exception as e:
        logger.error(f"ARP scan failed: {e}")
    
    return devices


def scan_arp_fast(subnet: str = "192.168.1.0/24", timeout: int = 1) -> list[dict]:
    """
    Fast ARP scan (reduced timeout, fewer retries).
    Good for interactive UI calls where speed matters more than completeness.
    """
    return scan_arp(subnet, timeout=timeout)


def _normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        return ""
    if target.startswith("http://") or target.startswith("https://"):
        try:
            parsed = urlparse(target)
            return parsed.hostname or ""
        except Exception:
            return target
    return target


def scan_nmap(subnet: str = "192.168.1.0/24", arguments: str = "-sV -p 22,80,443,502,47808,5353,1900 -T4") -> list[dict]:
    """
    Perform optional nmap-based deep network discovery.

    Returns a list of dicts with keys: ip, mac, hostname, service_details.
    """
    if nmap is None:
        logger.error("python-nmap not installed; cannot perform nmap discovery")
        return []

    if not shutil.which("nmap"):
        logger.error("nmap binary not found on PATH; cannot perform deep nmap scan")
        return []

    hosts = ",".join([_normalize_target(part) for part in subnet.split(",") if _normalize_target(part)])
    if not hosts:
        logger.warning("No valid nmap targets provided")
        return []

    devices = []
    try:
        logger.info("Starting nmap deep scan on %s...", hosts)
        scanner = nmap.PortScanner()
        scanner.scan(hosts=hosts, arguments=arguments)

        for ip in scanner.all_hosts():
            host_data = scanner[ip]
            if host_data.get("status", {}).get("state") != "up":
                continue

            addresses = host_data.get("addresses", {})
            mac = addresses.get("mac", "UNKNOWN")
            hostname = "unknown"
            hostnames = host_data.get("hostnames", [])
            if hostnames:
                hostname = hostnames[0].get("name", hostname)

            service_list = []
            for proto in ["tcp", "udp"]:
                for port, port_data in host_data.get(proto, {}).items():
                    service_list.append({
                        "port": port,
                        "protocol": proto,
                        "name": port_data.get("name"),
                        "product": port_data.get("product"),
                        "version": port_data.get("version"),
                        "state": port_data.get("state"),
                    })

            devices.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname or ip,
                "service_details": service_list,
            })
        logger.info("Nmap deep scan complete: %d devices found", len(devices))
    except Exception as exc:
        logger.error("Nmap scan failed: %s", exc)
    return devices


def _bytes_to_ip(addr: bytes) -> str:
    try:
        if len(addr) == 4:
            return socket.inet_ntoa(addr)
        if len(addr) == 16:
            return socket.inet_ntop(socket.AF_INET6, addr)
    except Exception:
        pass
    return ""


def scan_mdns(timeout: float = 3.0, service_types: Optional[list[str]] = None) -> list[dict]:
    """
    Discover local mDNS/Bonjour services and return host IP/MAC candidates.

    Returns a list of dicts with keys: ip, name, service_type, port, properties.
    """
    if Zeroconf is None or ServiceBrowser is None or ServiceInfo is None:
        logger.error("zeroconf not installed; cannot perform mDNS discovery")
        return []

    if service_types is None:
        service_types = [
            "_http._tcp.local.",
            "_ipp._tcp.local.",
            "_ssh._tcp.local.",
            "_afpovertcp._tcp.local.",
            "_workstation._tcp.local.",
            "_smb._tcp.local.",
        ]

    records: dict[str, dict] = {}

    class MdnsListener:
        def add_service(self, zeroconf: Any, service_type: str, name: str) -> None:
            try:
                info = zeroconf.get_service_info(service_type, name, timeout=2000)
                if info is None:
                    return

                addresses = [
                    _bytes_to_ip(addr) for addr in info.addresses if _bytes_to_ip(addr)
                ]
                if not addresses:
                    return

                key = f"{service_type}|{name}"
                records[key] = {
                    "name": name,
                    "service_type": service_type,
                    "server": info.server,
                    "addresses": addresses,
                    "port": info.port,
                    "properties": {
                        k.decode("utf-8", errors="ignore"): v.decode("utf-8", errors="ignore")
                        for k, v in info.properties.items()
                        if isinstance(k, bytes) and isinstance(v, bytes)
                    },
                }
                logger.debug("mDNS discovered %s -> %s", name, addresses)
            except Exception as exc:
                logger.debug("mDNS service info read failed for %s: %s", name, exc)

    zeroconf = Zeroconf()
    try:
        for service_type in service_types:
            ServiceBrowser(zeroconf, service_type, MdnsListener())

        time.sleep(timeout)
    finally:
        zeroconf.close()

    return list(records.values())
