---
name: wireshark
description: Operator-assisted Wireshark workflows for network traffic capture, protocol analysis, and credential extraction
category: tools
tags: [network, analysis, packet-capture, operator-assisted]
---

# Wireshark

Network protocol analyzer for packet capture and deep inspection. Use for traffic analysis, credential extraction, protocol debugging, and verifying encryption.

## When to Request

- When analyzing network-level communication between services
- To verify TLS/SSL implementation and detect cleartext credentials
- For protocol-specific analysis (DNS, ARP, SMB, HTTP)
- When debugging application behavior at the network layer
- To capture and analyze traffic from MITM positions

## Operator-Assisted Workflow

1. Agent identifies what traffic to capture and between which endpoints
2. Agent provides capture filter and display filter specifications
3. Operator runs capture (Wireshark GUI or tshark CLI) and provides results
4. Agent analyzes extracted data: credentials, tokens, protocol anomalies
5. Agent uses findings to direct further attacks or validate vulnerabilities

## Key Commands (tshark CLI)

### Capture Traffic
```
tshark -i INTERFACE -w capture.pcap -f "host TARGET"
```

### HTTP Credential Extraction
```
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.host -e http.request.uri -e http.file_data
```

### DNS Queries
```
tshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name -e dns.a
```

### TLS Analysis
```
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name -e tls.handshake.ciphersuite
```

### SMB/Authentication
```
tshark -r capture.pcap -Y "ntlmssp.auth" -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain
```

### Follow TCP Stream
```
tshark -r capture.pcap -z follow,tcp,ascii,0
```

## Display Filters

- **HTTP**: `http.request`, `http.response.code == 200`, `http.cookie`
- **Credentials**: `http.authorization`, `ftp.request.command == "PASS"`, `smtp.auth`
- **DNS**: `dns`, `dns.qry.type == 1`, `dns.flags.response == 0`
- **TLS**: `tls`, `tls.alert_message`, `tls.handshake`
- **ARP**: `arp`, `arp.duplicate-address-detected`
- **TCP**: `tcp.flags.syn == 1 && tcp.flags.ack == 0` (SYN only)

## Output Analysis

- **Cleartext credentials** -- HTTP Basic, FTP, SMTP, Telnet passwords captured in transit
- **Session tokens** -- cookies and auth tokens in unencrypted traffic
- **DNS queries** -- reveal internal hostnames, service discovery, data exfiltration channels
- **TLS versions and ciphers** -- identify weak encryption (SSLv3, TLS 1.0, weak ciphers)
- **ARP anomalies** -- detect ARP spoofing or identify network topology
- **Protocol errors** -- retransmissions, resets indicating network issues or security controls

## Integration with Strix

- Traffic analysis validates findings from application-level Strix testing
- Cleartext credentials discovered feed into credential reuse testing
- DNS analysis reveals internal architecture for expanded testing scope
- TLS analysis confirms encryption weaknesses identified by other tools
