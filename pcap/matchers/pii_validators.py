import re
import ipaddress
import uuid

def validate_luhn(value: str) -> bool:
    """Validates a numeric string using the Luhn algorithm (mod 10)."""
    digits = [int(c) for c in value if c.isdigit()]
    if not digits:
        return False
        
    checksum = 0
    reverse_digits = digits[::-1]
    
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
        
    return checksum % 10 == 0

def validate_e164(value: str) -> bool:
    """Validates a phone number loosely according to E.164 (max 15 digits)."""
    clean_val = re.sub(r'[\s\-()]', '', value)
    if not clean_val.startswith('+'):
        return False
    digits_only = clean_val[1:]
    return digits_only.isdigit() and 6 <= len(digits_only) <= 15

def validate_email(value: str) -> bool:
    """Validates basic email structure."""
    if not value or '@' not in value:
        return False
    parts = value.split('@')
    if len(parts) != 2:
        return False
    if not parts[0] or not parts[1]:
        return False
    if '.' not in parts[1]:
        return False
    return True

def validate_uuid(value: str) -> bool:
    """Validates UUID structure."""
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False

def validate_ipv4(value: str) -> bool:
    """Validates IPv4 octets."""
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4
    except ValueError:
        return False

def validate_latitude(value: str) -> bool:
    """Validates latitude is between -90 and 90."""
    try:
        val = float(value)
        return -90.0 <= val <= 90.0
    except ValueError:
        return False

def validate_longitude(value: str) -> bool:
    """Validates longitude is between -180 and 180."""
    try:
        val = float(value)
        return -180.0 <= val <= 180.0
    except ValueError:
        return False

# Registry matching pattern_name to validator function
VALIDATOR_REGISTRY = {
    "IMEI": validate_luhn,
    "ICCID": validate_luhn,
    "Credit Card": validate_luhn,
    "Phone Number": validate_e164,
    "Email Address": validate_email,
    "UUID": validate_uuid,
    "IPv4": validate_ipv4,
    "Latitude": validate_latitude,
    "Longitude": validate_longitude
}
