# Network-Scanner
A Python desktop application that scans a local network for connected devices

# dependecies
nmap, ncap

# build command
``` bash
pyinstaller --onefile  --windowed  scan.py
```

```
# input
ip range
## example
```
192.168.1.1-192.168.1.254 /
**OR** /
192.168.0.1-192.168.50.255 /
but it's more slowly /

## ping timeout in sec

## count of threads


