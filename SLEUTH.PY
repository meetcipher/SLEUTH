import subprocess
import nmap

class SLEUTH:
    def __init__(self):
        self.arp_scan_results = []
        self.icmp_scan_results = []

    def arp_scan(self):
        """Performs an ARP scan and returns a list of results."""
        arp_scan_results = subprocess.check_output(["arp", "-a"]).decode().splitlines()
        self.arp_scan_results = [result.split() for result in arp_scan_results]

    def icmp_scan(self):
        """Performs an ICMP scan and returns a list of results."""
        icmp_scan_results = subprocess.check_output(["nmap", "-sn", "--max-rtt", "1", "-Pn", "-6", "192.168.1.0/24"]).decode().splitlines()
        self.icmp_scan_results = [result.split() for result in icmp_scan_results]

    def get_device_info(self, ip_address):
        """Returns a dictionary of information about the device at the specified IP address."""
        device_info = {}
        for result in self.arp_scan_results:
            if result[1] == ip_address:
                device_info["mac_address"] = result[2]
                break

        for result in self.icmp_scan_results:
            if result[0] == ip_address:
                device_info["hostname"] = result[1]
                break

        # Get the device's running operating system using nmap.
        nmap_scan_results = nmap.PortScanner().scan(ip_address, arguments="-O")
        if "osclass" in nmap_scan_results["scan"][ip_address]:
            device_info["operating_system"] = nmap_scan_results["scan"][ip_address]["osclass"]["osfamily"]

        # Get the device's open ports using nmap.
        nmap_scan_results = nmap.PortScanner().scan(ip_address, arguments="-sS -T4")
        open_ports = []
        for port in nmap_scan_results["scan"][ip_address]["tcp"]:
            if port["state"] == "open":
                open_ports.append(port["port"])

        device_info["open_ports"] = open_ports

        return device_info

    def scan(self):
        """Performs an ARP scan and an ICMP scan, and returns a list of dictionaries containing information about the devices found."""
        self.arp_scan()
        self.icmp_scan()

        devices = []
        for ip_address in self.icmp_scan_results:
            device_info = self.get_device_info(ip_address[0])
            devices.append(device_info)

        return devices

if __name__ == "__main__":
    sleuth = SLEUTH()
    devices = sleuth.scan()

    for device in devices:
        print(f"Device IP: {device['ip_address']}")
        print(f"Device hostname: {device['hostname']}")
        print(f"Device operating system: {device['operating_system']}")
        print(f"Device open ports: {device['open_ports']}")
