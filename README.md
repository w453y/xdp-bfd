# OpenMPTCProuter Interface Statistics Monitor

This script monitors real-time network traffic and performance metrics across multiple network interfaces in an OpenMPTCProuter (OMR) environment. It tracks throughput, latency, and the physical packet distribution (load balancing splits) across multiple connections.

## Important Note on Interface Names

In OpenMPTCProuter, when you create an interface (e.g., `wan1`, `wwan`, `wan2`), you assign it a physical network device to use, such as `usb0` (for USB tethering), `phy0-sta0` (for Wi-Fi), `eth0`, etc. 

**CRITICAL:** This script requires the actual **network device names** (e.g., `usb0`, `phy0-sta0`), **NOT** the purely logical OMR interface names (e.g., `wan1`).

To safely determine the correct names:
1. SSH into your OpenMPTCProuter.
2. Run `ifconfig` or `ip link`.
3. Note the exact names of the physical devices you wish to monitor.

Because the monitoring operates at the low-level operating system tier rather than the OMR logical tier, providing the physical device names ensures accurate network statistics.

## Monitored Statistics

For each specified network device, the script calculates and records the following metrics:
- **rx_pps**: Received Packets Per Second 
- **tx_pps**: Transmitted Packets Per Second
- **rx_bps**: Received bits per second (throughput)
- **tx_bps**: Transmitted bits per second (throughput)
- **lat(ms)**: Latency in milliseconds (measured by pinging a target IP through the specific interface)
- **rx_split_%**: The percentage of the received traffic that went through this specific interface (**measured relative only to the combined total traffic of the specific interfaces you asked to monitor**).
- **tx_split_%**: The percentage of the transmitted traffic that went through this specific interface (**measured relative only to the combined total traffic of the specific interfaces you asked to monitor**).

## How to Use

1. **SSH into your OMR device:**
   Access your router via SSH with the root user.
   ```bash
   ssh root@192.168.100.1  # Replace with your OMR's actual IP address
   ```

2. **Upload/Transfer the script:**
   Ensure `monitor_ifstats.sh` is uploaded to your router and has executable permissions:
   ```bash
   chmod +x monitor_ifstats.sh
   ```

3. **Run the script before testing:**
   Start the monitoring script **before** running your network tests to capture all the relevant data. Supply the network device names separated by commas using the `-i` flag.
   
   *Example Usage:*
   ```bash
   ./monitor_ifstats.sh -i usb0,phy0-sta0,eth1
   ```

4. **Additional Options:**
   - `-i`: Comma-separated list of interfaces to monitor (e.g., `usb0,eth0`). Default is `eth0`.
   - `-t`: Target IP address to ping for latency measurement. Default is `8.8.8.8`.
   - `-n`: Polling interval in seconds. Default is `1`.
   - `-o`: Output file to log the data. Default is `netstats.log`.
   
   *Advanced Example:*
   ```bash
   ./monitor_ifstats.sh -i usb0,phy0-sta0 -t 1.1.1.1 -n 2 -o my_custom_test.log
   ```

## Example Output

The script constantly prints the statistics to your terminal and saves them simultaneously to the specified log file (e.g., `netstats.log`).

You can check out `example.log` in this repository to see a sample of exactly what the generated logs and captured data will look like!
