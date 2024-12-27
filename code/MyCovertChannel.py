from CovertChannelBase import CovertChannelBase
import struct
from scapy.all import IP, UDP, Raw, sniff
import time

class MyCovertChannel(CovertChannelBase):
    """
    Implements a covert channel using the Mode field in NTP packets for communication.
    The `send` method sends a binary message encoded in the Mode field, and the `receive` 
    method decodes the message received in the Mode field of incoming packets.
    """
    def __init__(self):
        """
        Initialize the covert channel class by calling the parent class initializer.
        This ensures any inherited functionality from CovertChannelBase is correctly set up.
        """
        super().__init__()
        

    def send(self, log_file_name, parameter1, parameter2):
        """
        Sends a binary message over a covert channel using the Mode field in NTP packets
        and measures the transmission time to compute channel capacity.
        """
        # Generate a random binary message with logging
        binary_message = self.generate_random_binary_message_with_logging(log_file_name, 16, 16)
        binary_message += '.'  # Append '.' as a breaker to signal the end of communication

        # Use parameter1 as server address and parameter2 as port
        ntp_server = parameter1
        port = parameter2

        # Start the timer
        start_time = time.time()

        # Send each bit in the binary message
        for bit in binary_message:
            mode = 7 if bit == '.' else int(bit)  # Use mode 7 for the breaker, otherwise the bit value
            packet = self.create_ntp_packet(mode)
            self.send_ntp_packet(ntp_server, port, packet)

        # Stop the timer
        end_time = time.time()

        # Calculate total time taken
        total_time = end_time - start_time

        # Log the results
        message_length = 128  # Length of the binary message (in bits, including the breaker)
        capacity_bps = message_length / total_time  # Compute capacity in bits per second
        
        # Print the results
        print(f"Message Length: 128 bits")
        print(f"Time Taken: {total_time:.6f} seconds")
        print(f"Covert Channel Capacity: {capacity_bps:.2f} bps")

            
    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        Receives and decodes a message from the Mode field of incoming NTP packets.

        Parameters:
        - parameter1: Placeholder parameter; not currently used.
        - parameter2: The source port to filter incoming packets (typically port 123).
        - parameter3: Placeholder parameter; not currently used.
        - log_file_name: The name of the log file to store the decoded message for verification.
        """
        received_message = []  # List to store the extracted binary message
        self.stop_sniffing = False  # Flag to signal when to stop sniffing for packets

        def packet_callback(packet):
            """
            Callback function invoked for each sniffed packet. Decodes the Mode field and appends it to the message.
            """
            # Check if the packet is a UDP packet and matches the specified source port
            if packet.haslayer(UDP) and packet[UDP].sport == parameter2:
                # Extract the Mode field from the NTP packet payload
                mode = self.extract_mode_from_packet(bytes(packet[UDP].payload))
                
                # Append the decoded mode as a string to the received message
                received_message.append(str(mode))
                
                # Stop sniffing if the breaker mode (7) is detected
                if mode == 7:
                    self.stop_sniffing = True

        # Filter for UDP packets on the specified port
        sniff_filter = f"udp port {parameter2}"

        # Start sniffing packets; stop when self.stop_sniffing is True
        sniff(
            filter=sniff_filter,
            prn=packet_callback,
            stop_filter=lambda _: self.stop_sniffing
        )

        # Decode the received message and remove the breaker (7) if present
        binary_message = ''.join(received_message).replace('7', '')  # Remove breaker '7'
        
        # Convert the binary message back into characters
        decoded_message = ''.join(self.convert_eight_bits_to_character(binary_message[i:i+8])
                                  for i in range(0, len(binary_message), 8))

        # Log the decoded message to the specified file
        self.log_received_message(log_file_name, decoded_message)
        

    def create_ntp_packet(self, mode):
        """
        Creates an NTP packet with the Mode field set to the specified value.

        Parameters:
        - mode: The value to set in the Mode field of the NTP packet (last 3 bits of the first byte).
        
        Returns:
        - A byte-encoded NTP packet with the Mode field set.
        """
        # NTP packet format: https://tools.ietf.org/html/rfc5905
        # Mode field is encoded in the last 3 bits of the first byte
        first_byte = (0 << 6) | (3 << 3) | mode  # LI = 0, VN = 3, Mode = mode
        packet = struct.pack('!B', first_byte) + b'\x00' * 47  # Rest of the packet is zeroed
        return packet


    def send_ntp_packet(self, ntp_server, port, packet):
        """
        Sends an NTP packet to the specified server and port.

        Parameters:
        - ntp_server: The IP address or hostname of the destination server.
        - port: The port on the destination server (typically 123).
        - packet: The crafted NTP packet to send.
        """
        ip = IP(dst=ntp_server)  # Create an IP layer targeting the server
        udp = UDP(sport=port, dport=port)  # Set the UDP source and destination ports
        raw = Raw(load=packet)  # Wrap the NTP packet in a Raw layer
        CovertChannelBase.send(self, ip / udp / raw)  # Use the provided send function from the base class


    def extract_mode_from_packet(self, packet):
        """
        Extracts the Mode field from an incoming NTP packet.

        Parameters:
        - packet: The raw payload of the NTP packet.
        
        Returns:
        - The value of the Mode field (last 3 bits of the first byte).
        """
        first_byte = struct.unpack('!B', packet[:1])[0]  # Get the first byte of the packet
        mode = first_byte & 0x07  # Extract the last 3 bits
        return mode


    def log_received_message(self, log_file_name, message):
        """
        Logs the received and decoded message to a specified file.

        Parameters:
        - log_file_name: The file name where the decoded message will be saved.
        - message: The decoded message to log.
        """
        with open(log_file_name, 'w') as log_file:
            log_file.write(message)
