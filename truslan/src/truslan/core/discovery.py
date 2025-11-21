"""
Cross-platform network discovery for truslan.

Discovers local network CIDRs using OS-native structured outputs.
No regex parsing - uses JSON/structured data where possible.
"""

import platform
import subprocess
import json
import logging
import re
from typing import List, Optional, Set
from pathlib import Path

logger = logging.getLogger("truslan")


def discover_local_networks() -> List[str]:
    """
    Discover local network CIDRs using OS-specific methods.

    Returns:
        List of CIDR strings (e.g., ["192.168.1.0/24", "10.0.0.0/24"])
    """
    system = platform.system()

    logger.info(f"Discovering local networks on {system}")

    if system == "Windows":
        return _discover_windows()
    elif system == "Linux":
        return _discover_linux()
    elif system == "Darwin":
        return _discover_macos()
    else:
        logger.warning(f"Unsupported platform: {system}")
        return []


def _discover_windows() -> List[str]:
    """
    Discover networks on Windows using PowerShell.

    Uses Get-NetIPConfiguration for structured JSON output.
    """
    logger.debug("Using PowerShell Get-NetIPConfiguration")

    try:
        # PowerShell command to get network configuration as JSON
        ps_command = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetIPConfiguration | ConvertTo-Json -Depth 10"
        ]

        result = subprocess.run(
            ps_command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )

        if result.returncode != 0:
            logger.warning(f"PowerShell command failed: {result.stderr}")
            return _discover_windows_fallback()

        # Parse JSON output
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse PowerShell JSON: {e}")
            return _discover_windows_fallback()

        # Handle both single object and array
        if isinstance(data, dict):
            data = [data]

        cidrs = set()

        for interface in data:
            # Skip interfaces without IPv4 addresses
            ipv4_config = interface.get("IPv4Address")
            if not ipv4_config:
                continue

            # Handle both single address and array
            if isinstance(ipv4_config, dict):
                ipv4_config = [ipv4_config]

            for addr_info in ipv4_config:
                ip = addr_info.get("IPAddress")
                prefix_length = addr_info.get("PrefixLength")

                if ip and prefix_length:
                    try:
                        cidr = _calculate_network_cidr(ip, prefix_length)
                        if cidr and not _is_loopback_network(cidr):
                            cidrs.add(cidr)
                    except Exception as e:
                        logger.debug(f"Error calculating CIDR for {ip}/{prefix_length}: {e}")

        result_list = sorted(list(cidrs))
        if result_list:
            logger.info(f"Discovered {len(result_list)} networks: {result_list}")
            return result_list

        logger.info("PowerShell discovery returned no networks, falling back to ipconfig parsing")
        return _discover_windows_fallback()

    except subprocess.TimeoutExpired:
        logger.warning("PowerShell command timed out")
        return _discover_windows_fallback()
    except Exception as e:
        logger.warning(f"Error in Windows discovery: {e}")
        return _discover_windows_fallback()


def _discover_windows_fallback() -> List[str]:
    """Fallback Windows discovery using ipconfig."""
    logger.debug("Using ipconfig fallback")

    try:
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )

        if result.returncode != 0:
            return []

        cidrs = set()
        current_ip = None
        current_mask = None

        for raw_line in result.stdout.split('\n'):
            line = raw_line.strip()
            if not line:
                continue

            lower_line = line.lower()
            normalized = lower_line.replace('.', ' ')

            # Detect IPv4 address lines using robust regex (ignoring label text encoding)
            # Matches lines like "   [Label] . . . : 192.168.1.130"
            if ":" in line:
                # Look for IP pattern at the end of the line
                ip_match = re.search(r':\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    ip_str = ip_match.group(1)
                    
                    # Determine if this is an IP or a Subnet Mask based on keywords or values
                    # Keywords: "subnet", "mask", "subred", "máscara" (and variations)
                    is_mask_label = any(kw in normalized for kw in ["subnet", "mask", "subred", "mscara", "máscara", "mascara"])
                    
                    # Also check values: Masks usually start with 255 or 0
                    is_mask_value = ip_str.startswith("255.") or ip_str.startswith("0.")
                    
                    # Keywords for IP: "ipv4", "address", "dirección", "direccion"
                    is_ip_label = any(kw in normalized for kw in ["ipv4", "address", "dirección", "direccion", "ip-address"])

                    if is_mask_label:
                        current_mask = ip_str
                    elif is_ip_label:
                        current_ip = ip_str
                    elif is_mask_value and not current_mask:
                        # Fallback: if it looks like a mask and we don't have one, assume it is
                        current_mask = ip_str
                    elif not current_mask and not current_ip:
                        # Fallback: if we have neither, and it's not a mask value, assume IP
                        # This is risky but covers cases where encoding destroys all keywords
                        # But we should be careful not to pick up Gateway or DHCP
                        # Gateways usually come AFTER IP/Mask.
                        # So if we see an IP-like value and haven't seen anything yet...
                        pass

                if current_ip and current_mask:
                    try:
                        prefix_length = _netmask_to_prefix(current_mask)
                        cidr = _calculate_network_cidr(current_ip, prefix_length)
                        if cidr and not _is_loopback_network(cidr):
                            cidrs.add(cidr)
                    except Exception as e:
                        logger.debug(f"Failed to process IP/Mask pair {current_ip}/{current_mask}: {e}")

                    current_ip = None
                    current_mask = None
                continue

            # Reset context when encountering adapter headings (e.g., "Ethernet adapter ...")
            if line.endswith(":") and not line.strip().startswith(":") and "." not in line[:10]:
                current_ip = None
                current_mask = None

        result_list = sorted(list(cidrs))
        logger.info(f"Discovered {len(result_list)} networks (fallback): {result_list}")
        return result_list

    except Exception as e:
        logger.error(f"Windows fallback discovery failed: {e}")
        return []


def _discover_linux() -> List[str]:
    """
    Discover networks on Linux using ip command with JSON output.
    """
    logger.debug("Using 'ip -j addr' command")

    try:
        # Try ip -j addr for JSON output
        result = subprocess.run(
            ["ip", "-j", "addr"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )

        if result.returncode != 0:
            logger.warning("'ip -j addr' failed, trying fallback")
            return _discover_linux_fallback()

        try:
            interfaces = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse 'ip -j addr' output: {e}")
            return _discover_linux_fallback()

        cidrs = set()

        for interface in interfaces:
            # Skip loopback interfaces
            if interface.get("ifname") == "lo":
                continue

            # Get address info
            addr_info_list = interface.get("addr_info", [])
            for addr_info in addr_info_list:
                # Only process IPv4
                if addr_info.get("family") != "inet":
                    continue

                local_ip = addr_info.get("local")
                prefix_len = addr_info.get("prefixlen")

                if local_ip and prefix_len:
                    try:
                        cidr = _calculate_network_cidr(local_ip, prefix_len)
                        if cidr and not _is_loopback_network(cidr):
                            cidrs.add(cidr)
                    except Exception as e:
                        logger.debug(f"Error calculating CIDR for {local_ip}/{prefix_len}: {e}")

        result_list = sorted(list(cidrs))
        logger.info(f"Discovered {len(result_list)} networks: {result_list}")
        return result_list

    except subprocess.TimeoutExpired:
        logger.warning("'ip -j addr' timed out")
        return _discover_linux_fallback()
    except FileNotFoundError:
        logger.warning("'ip' command not found, trying fallback")
        return _discover_linux_fallback()
    except Exception as e:
        logger.warning(f"Error in Linux discovery: {e}")
        return _discover_linux_fallback()


def _discover_linux_fallback() -> List[str]:
    """Fallback Linux discovery using ifconfig or ip addr."""
    logger.debug("Using ifconfig/ip addr fallback")

    # Try ifconfig first
    try:
        result = subprocess.run(
            ["ifconfig"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )

        if result.returncode == 0:
            return _parse_ifconfig_output(result.stdout)
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # Try ip addr (non-JSON)
    try:
        result = subprocess.run(
            ["ip", "addr"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )

        if result.returncode == 0:
            return _parse_ip_addr_output(result.stdout)
    except Exception:
        pass

    logger.error("All Linux discovery methods failed")
    return []


def _discover_macos() -> List[str]:
    """
    Discover networks on macOS using ifconfig.
    """
    logger.debug("Using macOS ifconfig")

    try:
        result = subprocess.run(
            ["ifconfig"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )

        if result.returncode != 0:
            logger.warning("ifconfig failed")
            return []

        return _parse_ifconfig_output(result.stdout)

    except Exception as e:
        logger.error(f"macOS discovery failed: {e}")
        return []


def _parse_ifconfig_output(output: str) -> List[str]:
    """Parse ifconfig output to extract network CIDRs."""
    cidrs = set()
    current_interface = None

    for line in output.split('\n'):
        # New interface line (starts without whitespace)
        if line and not line[0].isspace():
            current_interface = line.split(':')[0].strip()

        # Skip loopback
        if current_interface == "lo" or current_interface == "lo0":
            continue

        # Look for inet lines
        if 'inet ' in line and 'inet6' not in line:
            parts = line.strip().split()
            try:
                inet_idx = parts.index('inet')
                if inet_idx + 1 < len(parts):
                    ip = parts[inet_idx + 1]

                    # Find netmask
                    prefix_len = None
                    if 'netmask' in parts:
                        netmask_idx = parts.index('netmask')
                        if netmask_idx + 1 < len(parts):
                            netmask = parts[netmask_idx + 1]
                            # Handle hex format (0xffffff00) or dotted decimal
                            if netmask.startswith('0x'):
                                prefix_len = _hex_netmask_to_prefix(netmask)
                            else:
                                prefix_len = _netmask_to_prefix(netmask)

                    if ip and prefix_len:
                        cidr = _calculate_network_cidr(ip, prefix_len)
                        if cidr and not _is_loopback_network(cidr):
                            cidrs.add(cidr)
            except (ValueError, IndexError) as e:
                logger.debug(f"Error parsing ifconfig line: {line}, error: {e}")

    result_list = sorted(list(cidrs))
    logger.info(f"Discovered {len(result_list)} networks: {result_list}")
    return result_list


def _parse_ip_addr_output(output: str) -> List[str]:
    """Parse 'ip addr' output to extract network CIDRs."""
    cidrs = set()

    for line in output.split('\n'):
        line = line.strip()

        # Look for inet lines with CIDR notation
        if line.startswith('inet ') and not line.startswith('inet6'):
            parts = line.split()
            if len(parts) >= 2:
                addr_with_prefix = parts[1]

                # Should be in format: 192.168.1.10/24
                if '/' in addr_with_prefix:
                    ip, prefix_str = addr_with_prefix.split('/', 1)
                    try:
                        prefix_len = int(prefix_str)
                        cidr = _calculate_network_cidr(ip, prefix_len)
                        if cidr and not _is_loopback_network(cidr):
                            cidrs.add(cidr)
                    except ValueError:
                        pass

    result_list = sorted(list(cidrs))
    logger.info(f"Discovered {len(result_list)} networks: {result_list}")
    return result_list


def _calculate_network_cidr(ip: str, prefix_length: int) -> Optional[str]:
    """
    Calculate network CIDR from IP address and prefix length.

    Args:
        ip: IP address string
        prefix_length: Prefix length (e.g., 24 for /24)

    Returns:
        CIDR string (e.g., "192.168.1.0/24") or None if invalid
    """
    import ipaddress

    try:
        ip_obj = ipaddress.ip_address(ip)

        # Skip IPv6 for now
        if ip_obj.version != 4:
            return None

        # Create network object (strict=False allows host bits)
        network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
        return str(network)

    except (ValueError, ipaddress.AddressValueError) as e:
        logger.debug(f"Invalid IP/prefix: {ip}/{prefix_length}, error: {e}")
        return None


def _is_loopback_network(cidr: str) -> bool:
    """Check if CIDR is a loopback network."""
    return cidr.startswith("127.") or cidr == "::1/128"


def _netmask_to_prefix(netmask: str) -> int:
    """
    Convert dotted decimal netmask to prefix length.

    Args:
        netmask: Netmask string (e.g., "255.255.255.0")

    Returns:
        Prefix length (e.g., 24)
    """
    import ipaddress

    try:
        # Parse as IPv4 address
        mask = ipaddress.IPv4Address(netmask)
        # Convert to integer and count leading 1 bits
        mask_int = int(mask)

        # Count consecutive 1 bits from the left
        prefix_len = 0
        for i in range(32):
            if mask_int & (1 << (31 - i)):
                prefix_len += 1
            else:
                break

        return prefix_len

    except Exception as e:
        logger.debug(f"Error converting netmask {netmask}: {e}")
        # Common defaults
        if netmask == "255.255.255.0":
            return 24
        elif netmask == "255.255.0.0":
            return 16
        elif netmask == "255.0.0.0":
            return 8
        else:
            return 24  # Safe default


def _hex_netmask_to_prefix(hex_mask: str) -> int:
    """
    Convert hexadecimal netmask to prefix length.

    Args:
        hex_mask: Hex mask string (e.g., "0xffffff00")

    Returns:
        Prefix length (e.g., 24)
    """
    try:
        mask_int = int(hex_mask, 16)

        # Count consecutive 1 bits from the left
        prefix_len = 0
        for i in range(32):
            if mask_int & (1 << (31 - i)):
                prefix_len += 1
            else:
                break

        return prefix_len

    except Exception as e:
        logger.debug(f"Error converting hex mask {hex_mask}: {e}")
        return 24  # Safe default


def validate_discovery() -> bool:
    """
    Validate that network discovery works on this platform.

    Returns:
        True if at least one network was discovered
    """
    try:
        networks = discover_local_networks()
        return len(networks) > 0
    except Exception as e:
        logger.error(f"Discovery validation failed: {e}")
        return False
