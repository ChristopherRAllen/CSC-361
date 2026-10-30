
class TCPPacket:
    def __init__(self):
        # Store the packet's IP addresses and ports
        self.source_ip = ""
        self.destination_ip = ""
        self.source_port = 0
        self.destination_port = 0

        # Store TCP information
        self.sequence_number = 0
        self.ack_number = 0
        self.syn = False
        self.fin = False
        self.rst = False
        self.ack = False
        self.window_size = 0
        self.data_size = 0
        self.timestamp = 0.0


class TCPConnection:
    def __init__(self, first_packet):
        # Store the connection's source and destination
        self.source_ip = first_packet.source_ip
        self.destination_ip = first_packet.destination_ip
        self.source_port = first_packet.source_port
        self.destination_port = first_packet.destination_port

        # Store packets and TCP flags
        self.packets = []
        self.syn_count = 0
        self.fin_count = 0
        self.reset = False

        # Store connection times
        self.start_time = None
        self.end_time = None

        # Store packet and byte counts
        self.source_packets = 0
        self.destination_packets = 0
        self.source_bytes = 0
        self.destination_bytes = 0

        # Store window sizes and RTT values
        self.window_sizes = []
        self.rtt_values = []

        # Check whether the connection started before capture
        self.established_before_capture = not first_packet.syn

        # Remember whether data was sent after a FIN
        self.data_after_fin = False

    def add_packet(self, packet):
        # Add the packet to this connection
        self.packets.append(packet)

        # Count SYN packets
        if packet.syn:
            self.syn_count += 1

            if self.start_time is None:
                self.start_time = packet.timestamp

        # Check for data after an earlier FIN
        if self.fin_count > 0 and packet.data_size > 0:
            self.data_after_fin = True

        # Count FIN packets
        if packet.fin:
            self.fin_count += 1
            self.end_time = packet.timestamp

        # Check for reset packets
        if packet.rst:
            self.reset = True

        # Count packets and data bytes in each direction
        if (packet.source_ip == self.source_ip and
                packet.source_port == self.source_port):
            self.source_packets += 1
            self.source_bytes += packet.data_size
        else:
            self.destination_packets += 1
            self.destination_bytes += packet.data_size

        # Store the advertised window size
        self.window_sizes.append(packet.window_size)

    def is_complete(self):
        # A complete connection has at least one SYN and FIN
        return self.syn_count > 0 and self.fin_count > 0

    def get_status(self):
        # Build the connection's status
        status = "S" + str(self.syn_count)
        status += "F" + str(self.fin_count)

        if self.reset:
            status += "/R"

        return status

    def is_open(self):
        # Open if no FIN was seen or data followed a FIN
        return self.fin_count == 0 or self.data_after_fin

    def calculate_metrics(self):
        # Calculate RTT using the first matching ACK
        self.rtt_values = []

        for i in range(len(self.packets)):
            sent_packet = self.packets[i]

            # Only use packets containing data
            if sent_packet.data_size == 0:
                continue

            expected_ack = (
                sent_packet.sequence_number + sent_packet.data_size
            ) % (2 ** 32)

            # Search forward for a matching ACK
            for j in range(i + 1, len(self.packets)):
                ack_packet = self.packets[j]

                same_direction = (
                    sent_packet.source_ip == ack_packet.source_ip
                    and sent_packet.source_port == ack_packet.source_port
                )

                if same_direction:
                    continue

                if (ack_packet.ack and
                        ack_packet.ack_number == expected_ack):
                    rtt = ack_packet.timestamp - sent_packet.timestamp
                    self.rtt_values.append(rtt)
                    break

    def total_packets(self):
        # Return packets from both directions
        return self.source_packets + self.destination_packets

    def total_bytes(self):
        # Return data bytes from both directions
        return self.source_bytes + self.destination_bytes
