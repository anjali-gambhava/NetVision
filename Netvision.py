import pyshark
import matplotlib.pyplot as plt

def analyze_packets(file_path, protocol_filter=None, deep_inspection=False):
    # Open the capture file
    cap = pyshark.FileCapture(file_path)

    # Analyze packets
    for pkt in cap:
        if 'IP' in pkt:
            if pkt.transport_layer:
                # Extract packet information
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                protocol = pkt.transport_layer   
                src_port = pkt[pkt.transport_layer].srcport
                dst_port = pkt[pkt.transport_layer].dstport
                protocols = [layer.layer_name for layer in pkt.layers]

                # Apply protocol filter if specified
                if protocol_filter is not None and protocol != protocol_filter:
                    continue

                # Print packet information
                print(f'Source: {src_ip}:{src_port} -> Destination: {dst_ip}:{dst_port} ({", ".join(protocols)})')

                # Perform deep packet inspection if enabled
                if deep_inspection:
                    print(f'Packet Info: {pkt}')  # Print packet info
                    print(f'Target Address: {pkt.ip.dst}')  # Print target address

def traffic_visualization(file_path):
    # Open the capture file
    cap = pyshark.FileCapture(file_path)

    # Count packets by protocol
    protocols = {}
    for pkt in cap:
        if 'IP' in pkt:
            if pkt.transport_layer:
                protocol = pkt.transport_layer
                if protocol not in protocols:
                    protocols[protocol] = 1
                else:
                    protocols[protocol] += 1

    # Plot a bar chart of the packet counts
    plt.bar(protocols.keys(), protocols.values())
    plt.xlabel('Protocol')
    plt.ylabel('Packet Count')
    plt.show()

def detect_anomalies(file_path):
    # Open the capture file
    cap = pyshark.FileCapture(file_path)

    # Initialize counters for each protocol
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    arp_count = 0
    ssdp_count = 0
    tls_count = 0
    other_count = 0

    # Analyze packets
    for pkt in cap:
        if 'IP' in pkt:
            if pkt.transport_layer:
                # Extract packet information
                protocol = pkt.transport_layer

                # Update protocol counter
                if protocol == 'TCP':
                    tcp_count += 1
                elif protocol == 'UDP':
                    udp_count += 1
                elif protocol == 'ICMP':
                    icmp_count += 1
                elif protocol == 'ARP':
                    arp_count += 1
                elif protocol == 'SSDP':
                    ssdp_count += 1
                elif protocol == 'TLSv1.2':
                    tls_count += 1
                else:
                    other_count += 1

    # Check for anomalies
    if udp_count > tcp_count:
        print('Anomaly Detected: Unusual amount of UDP traffic compared to TCP traffic.')
    elif icmp_count > 100:
        print('Anomaly Detected: Unusual amount of ICMP traffic detected.')
    elif arp_count > 50:
        print('Anomaly Detected: Unusual amount of ARP traffic detected.')
    else:
        print('No anomalies detected.')

    # Plot protocol counters
    plt.bar(['TCP', 'UDP', 'ICMP', 'ARP', 'SSDP', 'TLS', 'Other'],
            [tcp_count, udp_count, icmp_count, arp_count, ssdp_count, tls_count, other_count])
    plt.xlabel('Protocols')
    plt.ylabel('Number of Packets')
    plt.title('Network Traffic Visualization')
    plt.show()

def menu():
    while True:
        print('-------------- Welcome To NetVision ---------------')
        print('1. Analyze all packets')
        print('2. Filter packets by protocol')
        print('3. Filter packets by protocol with deep packet inspection')
        print('4. Visualize packet traffic')
        print('5. Detect anomalies')
        print('6. Exit')

        choice = input('Enter your choice: ')

        if choice == '1':
            file_path = input('Enter the path of the capture file: ')
            analyze_packets(file_path)
        elif choice == '2':
            file_path = input('Enter the path of the capture file: ')
            protocol = input('Enter the protocol to filter (TCP, UDP, ICMP, ARP,SSDP,TLSv1.2,etc.): ').upper()
            analyze_packets(file_path, protocol_filter=protocol)
        elif choice == '3':
            file_path = input('Enter the path of the capture file: ')
            protocol = input('Enter the protocol to filter (TCP, UDP, ICMP, ARP,SSDP,TLSv1.2 etc.): ').upper()
            analyze_packets(file_path, protocol_filter=protocol, deep_inspection=True)
        elif choice == '4':
            traffic_visualization(file_path)
        elif choice == '5':
            file_path = input('Enter the path of the capture file: ')
            detect_anomalies(file_path)
        elif choice == '6':
            break  # Exit the while loop
        else:
            print('Invalid choice. Please try again.')

if __name__ == '__main__':
    menu()