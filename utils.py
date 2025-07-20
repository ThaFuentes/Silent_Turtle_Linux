# utils.py
import re

def parse_dwell(txt):
    """
    Parses a dwell time string like '5s', '1m', '2h', '1d' into seconds as a float.
    Returns None if the input is invalid.
    """
    pattern = r'^\s*(\d+(?:\.\d*)?)\s*([smhdSMHD]?)\s*$'
    match = re.match(pattern, txt)
    if not match:
        return None
    val, unit = match.groups()
    seconds = float(val)
    unit = unit.lower() or 's'  # default to seconds
    units_map = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
    return seconds * units_map[unit]
