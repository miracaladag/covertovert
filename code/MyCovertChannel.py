from CovertChannelBase import CovertChannelBase
import struct
from scapy.all import IP, UDP, Raw, sniff

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()

    def send(self, log_file_name, parameter1, parameter2):
        """
        This function generates a random binary message and sends it using the Mode field in NTP packets.
        """
        # Generate a random binary message with logging
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        binary_message += '.'  # Append '.' as a breaker to signal the end of communication

        # Use parameter1 as server address and parameter2 as port
        ntp_server = parameter1
        port = parameter2

        for bit in binary_message:
            mode = 7 if bit == '.' else int(bit)  # Use mode 7 for the breaker, otherwise the bit value
            packet = self.create_ntp_packet(mode)
            self.send_ntp_packet(ntp_server, port, packet)

    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        This function receives NTP packets and decodes the message from the Mode field.
        """
        received_message = []
        self.stop_sniffing = False  # Flag to stop sniffing

        def packet_callback(packet):
            if packet.haslayer(UDP) and packet[UDP].sport == parameter2:
                mode = self.extract_mode_from_packet(bytes(packet[UDP].payload))
                received_message.append(str(mode))  # Add mode to received message
                if mode == 7:  # Stop when breaker mode is detected
                    self.stop_sniffing = True  # Set flag to stop sniffing

        # Sniff filter for UDP traffic on the specified port
        sniff_filter = f"udp port {parameter2}"

        # Sniff packets and use stop_filter to monitor stopping condition
        sniff(
            filter=sniff_filter,
            prn=packet_callback,
            stop_filter=lambda _: self.stop_sniffing  # Stop based on the flag
        )

        # Decode the received message, removing the breaker '7' if present
        binary_message = ''.join(received_message).replace('7', '')  # Remove breaker '7'
        decoded_message = ''.join(self.convert_eight_bits_to_character(binary_message[i:i+8]) 
                                  for i in range(0, len(binary_message), 8))

        # Log the received message
        self.log_received_message(log_file_name, decoded_message)

    def create_ntp_packet(self, mode):
        """
        Create an NTP packet with the specified mode.
        """
        # NTP packet format: https://tools.ietf.org/html/rfc5905
        # Mode is in the last 3 bits of the first byte
        first_byte = (0 << 6) | (3 << 3) | mode  # LI = 0, VN = 3, Mode = mode
        packet = struct.pack('!B', first_byte) + b'\x00' * 47
        return packet

    def send_ntp_packet(self, ntp_server, port, packet):
        """
        Send an NTP packet to the specified server and port using the provided send function.
        """
        ip = IP(dst=ntp_server)
        udp = UDP(sport=port, dport=port)
        raw = Raw(load=packet)
        CovertChannelBase.send(self, ip/udp/raw)

    def extract_mode_from_packet(self, packet):
        """
        Extract the mode field from an NTP packet.
        """
        first_byte = struct.unpack('!B', packet[:1])[0]
        mode = first_byte & 0x07  # Last 3 bits
        return mode

    def log_received_message(self, log_file_name, message):
        """
        Log the received message to a file.
        """
        with open(log_file_name, 'w') as log_file:
            log_file.write(message)
