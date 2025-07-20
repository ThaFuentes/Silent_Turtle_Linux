#sys_helpers.py
import subprocess

def run_cmd(cmd):
    """
    Run a system command silently (suppress stdout and stderr).
    `cmd` is a list, e.g. ["sudo", "iw", "dev"]
    """
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def enable_monitor(iface):
    """
    Enable monitor mode on the specified interface.
    Uses airmon-ng to kill conflicting processes and start monitor mode.
    Returns the new monitor interface name or original if failed.
    """
    run_cmd(["sudo", "airmon-ng", "check", "kill"])
    run_cmd(["sudo", "airmon-ng", "start", iface])
    mon_iface = iface + "mon"
    # Check if monitor interface is created
    output = subprocess.getoutput("iw dev")
    if mon_iface in output:
        return mon_iface
    return iface

def set_channel(iface, channel):
    """
    Set the wifi interface channel.
    """
    run_cmd(["sudo", "iw", "dev", iface, "set", "channel", str(channel)])
