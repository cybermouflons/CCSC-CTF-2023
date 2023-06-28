import random
from scapy.all import *

def generate_pcap_file():
    # Create the Zigbee packets with fragments of the hidden flag
    flag = "CCSC{z1GbE3_pR0t0c01-m4T3_<3}"
    flag_fragments = [flag[i:i+3] for i in range(0, len(flag), 3)]

    # Generate random Zigbee MAC addresses
    src_mac = "00:11:22:33:44:55"
    dst_mac = "66:77:88:99:AA:BB"

    # Generate random noise data
    noise_length = random.randint(1000, 5000)
    noise_data = bytes([random.randint(0, 255) for _ in range(noise_length)])

    # Create a list of protocols
    protocols = [Ether, Dot1Q, IP, UDP, TCP, ICMP]

    # Create a list to store the generated packets
    packets = []

    # Generate random packets with various protocols
    for _ in range(2000):
        protocol = random.choice(protocols)

        # Generate random packet data
        if protocol == TCP:
            # Generate fake HTTP request data
            method = random.choice(["GET", "POST", "PUT", "DELETE"])
            path = "/AI/retaliation"
            headers = {
                "Host": "ccsc.cybermouflons.com",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
                "Referer": "https://ccsc.cybermouflons.com/TROLOLOLOLOL",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            http_request = f"{method} {path} HTTP/1.1\r\n"
            http_request += "\r\n".join([f"{header}: {value}" for header, value in headers.items()])
            packet_data = http_request.encode()
        elif protocol == TCP and random.random() < 0.5:
            # Generate fake FTP command data
            commands = ["USER government_agent", "PASS tH1s-15_mY_S3cUR3_p@@5w0Rd", "LIST", "RETR flag.txt", "QUIT"]
            ftp_command = random.choice(commands) + "\r\n"
            packet_data = ftp_command.encode()
        elif protocol == TCP and random.random() < 0.5:
            # Generate fake Telnet data
            telnet_data = "You have successfully connected to the AI Command and Control Server.\r\n"
            packet_data = telnet_data.encode()
        else:
            # Generate random packet data
            packet_data = bytes([random.randint(0, 255) for _ in range(random.randint(100, 500))])

        # Create the packet with the random data
        packet = protocol() / packet_data

        # Append the packet to the list
        packets.append(packet)

    # Create Zigbee packets with flag fragments
    for fragment in flag_fragments:
        # Create a Zigbee packet with fragment and noise data
        zigbee_header = b"\x03\x08\x00\x01\x00\x00\x00\x00\x00\x00"
        zigbee_payload = zigbee_header + noise_data + fragment.encode()
        zigbee_packet = RadioTap() / zigbee_payload

        # Insert the Zigbee packet at a random position
        random_position = random.randint(0, len(packets))
        packets.insert(random_position, zigbee_packet)

    # Shuffle the packets
    random.shuffle(packets)

    # Write the packets to a pcap file
    wrpcap("hidden_flag.pcap", packets)

    print("PCAP file 'hidden_flag.pcap' generated successfully.")

if __name__ == '__main__':
    generate_pcap_file()
