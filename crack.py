#crack.py
#!/usr/bin/env python3
import sys
import subprocess
import os

def main():
    if len(sys.argv) != 3:
        print("Usage: crack.py <handshake.cap> <password>")
        sys.exit(2)

    handshake, password = sys.argv[1], sys.argv[2]
    if not os.path.exists(handshake):
        print(f"Handshake file not found: {handshake}")
        sys.exit(3)

    # write single-password wordlist
    tmp = "temp_pass.txt"
    with open(tmp, "w") as f:
        f.write(password + "\n")

    # run aircrack-ng
    result = subprocess.run(
        ["aircrack-ng", "-a2", "-w", tmp, handshake],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True
    )
    os.remove(tmp)

    # aircrack-ng prints "KEY FOUND!" on success
    if "KEY FOUND!" in result.stdout:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
