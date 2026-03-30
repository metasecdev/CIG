"""
Deep Packet Inspection for PCAP files
Analyzes captured packets for IOCs and threats
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class PacketInfo:
    """Information extracted from a packet"""

    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    payload_preview: str
    dns_query: Optional[str] = None
    dns_answer: Optional[str] = None
    http_host: Optional[str] = None
    http_url: Optional[str] = None


class DeepPacketInspector:
    """Deep packet inspection for threat detection"""

    def __init__(self, threat_matcher=None):
        self.threat_matcher = threat_matcher
        self.indicators = {"ip": set(), "domain": set(), "url": set(), "hash": set()}

    def load_indicators(self, indicators: Dict[str, set]):
        """Load threat indicators for matching"""
        self.indicators = indicators

    def inspect_pcap(self, pcap_path: str) -> List[Dict[str, Any]]:
        """Inspect PCAP file and extract IOCs"""
        threats_found = []

        try:
            from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw

            packets = rdpcap(pcap_path)

            for pkt in packets:
                threat = self._inspect_packet(pkt)
                if threat:
                    threats_found.append(threat)

            logger.info(
                f"Inspected {len(packets)} packets, found {len(threats_found)} threats"
            )
        except Exception as e:
            logger.error(f"Error inspecting PCAP: {e}")

        return threats_found

    def _inspect_packet(self, pkt) -> Optional[Dict[str, Any]]:
        """Inspect a single packet for IOCs"""
        if not pkt.haslayer(IP):
            return None

        info = PacketInfo(
            timestamp=datetime.now().isoformat(),
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            src_port=pkt.sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else 0,
            dst_port=pkt.dport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else 0,
            protocol=pkt.proto if pkt.haslayer(IP) else "unknown",
            length=len(pkt),
            payload_preview=self._get_payload_preview(pkt),
        )

        if pkt.haslayer(DNS):
            info = self._extract_dns_info(pkt, info)

        threat = self._match_indicators(info)
        return threat

    def _get_payload_preview(self, pkt) -> str:
        """Extract payload preview from packet"""
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            try:
                return payload[:100].decode("utf-8", errors="ignore")
            except:
                return payload[:20].hex()
        return ""

    def _extract_dns_info(self, pkt, info: PacketInfo) -> PacketInfo:
        """Extract DNS query/answer info"""
        dns_layer = pkt[DNS]

        if dns_layer.qr == 0:
            if dns_layer.haslayer(DNSQR):
                info.dns_query = (
                    dns_layer[DNSQR].qname.decode() if dns_layer[DNSQR].qname else None
                )
        else:
            if dns_layer.haslayer(DNSRR):
                info.dns_answer = (
                    dns_layer[DNSRR].rdata if dns_layer[DNSRR].rdata else None
                )

        return info

    def _match_indicators(self, info: PacketInfo) -> Optional[Dict[str, Any]]:
        """Match packet info against threat indicators"""
        threats = []

        if info.src_ip in self.indicators.get("ip", set()):
            threats.append({"type": "ip", "value": info.src_ip, "direction": "src"})

        if info.dst_ip in self.indicators.get("ip", set()):
            threats.append({"type": "ip", "value": info.dst_ip, "direction": "dst"})

        if info.dns_query:
            for domain in self.indicators.get("domain", set()):
                if domain in info.dns_query:
                    threats.append(
                        {"type": "domain", "value": domain, "matched": info.dns_query}
                    )

        if threats:
            return {
                "timestamp": info.timestamp,
                "src_ip": info.src_ip,
                "dst_ip": info.dst_ip,
                "src_port": info.src_port,
                "dst_port": info.dst_port,
                "protocol": info.protocol,
                "threats": threats,
            }

        return None

    def extract_sessions(self, pcap_path: str) -> List[Dict[str, Any]]:
        """Extract session data from PCAP"""
        sessions = {}

        try:
            from scapy.all import rdpcap, IP, TCP

            packets = rdpcap(pcap_path)

            for pkt in packets:
                if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                    continue

                src = pkt[IP].src
                dst = pkt[IP].dst
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport

                session_key = f"{src}:{sport}-{dst}:{dport}"

                if session_key not in sessions:
                    sessions[session_key] = {
                        "src_ip": src,
                        "dst_ip": dst,
                        "src_port": sport,
                        "dst_port": dport,
                        "packets": 0,
                        "bytes": 0,
                        "first_seen": None,
                        "last_seen": None,
                    }

                sessions[session_key]["packets"] += 1
                sessions[session_key]["bytes"] += len(pkt)

            logger.info(f"Extracted {len(sessions)} sessions from PCAP")
        except Exception as e:
            logger.error(f"Error extracting sessions: {e}")

        return list(sessions.values())

    def extract_dns_queries(self, pcap_path: str) -> List[Dict[str, Any]]:
        """Extract all DNS queries from PCAP"""
        queries = []

        try:
            from scapy.all import rdpcap, IP, DNS, DNSQR

            packets = rdpcap(pcap_path)

            for pkt in packets:
                if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
                    query = pkt[DNSQR].qname
                    queries.append(
                        {
                            "timestamp": datetime.now().isoformat(),
                            "query": query.decode() if query else "",
                            "src_ip": pkt[IP].src if pkt.haslayer(IP) else "",
                            "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else "",
                        }
                    )

            logger.info(f"Extracted {len(queries)} DNS queries from PCAP")
        except Exception as e:
            logger.error(f"Error extracting DNS queries: {e}")

        return queries

    def extract_http_requests(self, pcap_path: str) -> List[Dict[str, Any]]:
        """Extract HTTP requests from PCAP"""
        requests = []

        try:
            from scapy.all import rdpcap, IP, TCP, Raw

            packets = rdpcap(pcap_path)

            for pkt in packets:
                if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                    continue

                payload = bytes(pkt[Raw].load)
                try:
                    payload_str = payload.decode("utf-8", errors="ignore")
                    if (
                        payload_str.startswith("GET ")
                        or payload_str.startswith("POST ")
                        or payload_str.startswith("HTTP/")
                    ):
                        requests.append(
                            {
                                "timestamp": datetime.now().isoformat(),
                                "src_ip": pkt[IP].src,
                                "dst_ip": pkt[IP].dst,
                                "src_port": pkt[TCP].sport,
                                "dst_port": pkt[TCP].dport,
                                "request": payload_str[:500],
                            }
                        )
                except:
                    pass

            logger.info(f"Extracted {len(requests)} HTTP requests from PCAP")
        except Exception as e:
            logger.error(f"Error extracting HTTP requests: {e}")

        return requests
