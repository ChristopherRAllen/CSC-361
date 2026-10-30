import sys
import struct


def read_pcap(path):
    # Read the PCAP file and return each packet with its timestamp
    with open(path, 'rb') as f:
        magic = f.read(4)

        formats = {
            b'\xd4\xc3\xb2\xa1': ('<', 1000000),
            b'\xa1\xb2\xc3\xd4': ('>', 1000000),
            b'\x4d\x3c\xb2\xa1': ('<', 1000000000),
            b'\xa1\xb2\x3c\x4d': ('>', 1000000000)
        }

        if magic not in formats:
            raise ValueError('Unsupported capture file format')

        endian, divisor = formats[magic]

        header = f.read(20)

        if len(header) != 20:
            raise ValueError('Invalid PCAP header')

        values = struct.unpack(endian + 'HHiIII', header)

        if values[5] != 1:
            raise ValueError('Expected Ethernet capture')

        origin = None

        while True:
            hdr = f.read(16)

            if not hdr:
                break

            if len(hdr) != 16:
                raise ValueError('Incomplete packet header')

            seconds, fraction, length, original_length = struct.unpack(
                endian + 'IIII', hdr
            )

            if length > 100000000:
                raise ValueError('Invalid packet length')

            frame = f.read(length)

            if len(frame) != length:
                raise ValueError('Incomplete packet data')

            timestamp = seconds + fraction / divisor

            if origin is None:
                origin = timestamp

            yield timestamp - origin, frame


def get_ip_address(data):
    # Convert four IP address bytes into a readable address
    numbers = struct.unpack('BBBB', data)

    return '{}.{}.{}.{}'.format(
        numbers[0],
        numbers[1],
        numbers[2],
        numbers[3]
    )


def parse_tcp(frame):
    # Extract the TCP information from an Ethernet packet
    if len(frame) < 14:
        return None

    ethertype = struct.unpack_from('!H', frame, 12)[0]
    ip_start = 14

    # Skip VLAN headers if present
    while ethertype in (0x8100, 0x88a8, 0x9100):
        if len(frame) < ip_start + 4:
            return None

        ethertype = struct.unpack_from(
            '!H', frame, ip_start + 2
        )[0]

        ip_start += 4

    # Only process IPv4 packets
    if ethertype != 0x0800:
        return None

    if len(frame) < ip_start + 20:
        return None

    version_ihl = frame[ip_start]

    version = version_ihl >> 4
    ip_header_length = (version_ihl & 15) * 4

    if version != 4 or ip_header_length < 20:
        return None

    if len(frame) < ip_start + ip_header_length:
        return None

    # Protocol 6 means TCP
    if frame[ip_start + 9] != 6:
        return None

    total_length = struct.unpack_from(
        '!H', frame, ip_start + 2
    )[0]

    fragment = struct.unpack_from(
        '!H', frame, ip_start + 6
    )[0]

    if fragment & 0x1fff:
        return None

    tcp_start = ip_start + ip_header_length
    ip_end = min(len(frame), ip_start + total_length)

    if total_length < ip_header_length + 20:
        return None

    if ip_end < tcp_start + 20:
        return None

    # Read the IP addresses
    source_ip = get_ip_address(
        frame[ip_start + 12:ip_start + 16]
    )

    destination_ip = get_ip_address(
        frame[ip_start + 16:ip_start + 20]
    )

    # Read TCP ports and sequence numbers
    source_port, destination_port, seq, ack = struct.unpack_from(
        '!HHII', frame, tcp_start
    )

    tcp_header_length = (frame[tcp_start + 12] >> 4) * 4

    if tcp_header_length < 20:
        return None

    if ip_end < tcp_start + tcp_header_length:
        return None

    flags = frame[tcp_start + 13]

    window = struct.unpack_from(
        '!H', frame, tcp_start + 14
    )[0]

    data_length = max(
        0,
        total_length - ip_header_length - tcp_header_length
    )

    return {
        'src': (source_ip, source_port),
        'dst': (destination_ip, destination_port),
        'seq': seq,
        'ack': ack,
        'syn': bool(flags & 0x02),
        'fin': bool(flags & 0x01),
        'rst': bool(flags & 0x04),
        'ack_flag': bool(flags & 0x10),
        'window': window,
        'data_len': data_length
    }


class Connection:
    # Store information about one TCP connection
    def __init__(self, first, time):
        self.src = first['src']
        self.dst = first['dst']

        self.first_time = time

        self.syn_times = []
        self.fin_times = []

        self.syn_count = 0
        self.fin_count = 0

        self.reset = False

        self.packets = [0, 0]
        self.bytes = [0, 0]

        self.windows = []
        self.events = []

        self.first_was_syn = first['syn']

        self.data_after_fin = False

    def add(self, p, t):
        # Determine which direction the packet was sent
        direction = 0 if p['src'] == self.src else 1

        self.packets[direction] += 1
        self.bytes[direction] += p['data_len']

        self.windows.append(p['window'])

        if p['syn']:
            self.syn_count += 1
            self.syn_times.append(t)

        # Reset the check whenever a new FIN arrives
        if p['fin']:
            self.fin_count += 1
            self.fin_times.append(t)
            self.data_after_fin = False

        elif self.fin_count > 0 and p['data_len'] > 0:
            self.data_after_fin = True

        if p['rst']:
            self.reset = True

        self.events.append((t, direction, p))

    @property
    def complete(self):
        return self.syn_count > 0 and self.fin_count > 0

    @property
    def is_open(self):
        # Open if no FIN or data arrived after the latest FIN
        return self.fin_count == 0 or self.data_after_fin

    @property
    def state(self):
        status = 'S{}F{}'.format(
            self.syn_count,
            self.fin_count
        )

        if self.reset:
            status += '/R'

        return status

    @property
    def start(self):
        if self.syn_times:
            return self.syn_times[0]

        return self.first_time

    @property
    def end(self):
        if self.fin_times:
            return self.fin_times[-1]

        return self.events[-1][0]

    def rtts(self):
        # Find the first matching ACK for each TCP data packet
        results = []

        for i, (sent_t, direction, p) in enumerate(self.events):
            consumed = p['data_len']

            if consumed == 0:
                continue

            expected = (p['seq'] + consumed) & 0xffffffff

            for recv_t, other_dir, reply in self.events[i + 1:]:
                if (
                    other_dir != direction
                    and reply['ack_flag']
                    and reply['ack'] == expected
                ):
                    results.append(recv_t - sent_t)
                    break

        return results


def stats(values):
    # Calculate minimum, average and maximum
    if not values:
        return None

    return (
        min(values),
        sum(values) / len(values),
        max(values)
    )


def analyze(path):
    # Group TCP packets into connections
    connections = {}

    for t, frame in read_pcap(path):
        p = parse_tcp(frame)

        if p is None:
            continue

        key_a = (p['src'], p['dst'])
        key_b = (p['dst'], p['src'])

        if key_a in connections:
            key = key_a

        elif key_b in connections:
            key = key_b

        else:
            key = key_a

        if key not in connections:
            connections[key] = Connection(p, t)

        connections[key].add(p, t)

    return list(connections.values())


def report(conns):
    # Print the results in the assignment's required format

    print('A) Total number of connections:', len(conns))
    print('_' * 48)

    print("\nB) Connection's details")

    for i, c in enumerate(conns, 1):
        print('\nConnection {}:'.format(i))

        print('Source Address:', c.src[0])
        print('Destination Address:', c.dst[0])
        print('Source Port:', c.src[1])
        print('Destination Port:', c.dst[1])
        print('Status:', c.state)

        if c.complete:
            print('Start time: {:.6f} seconds'.format(c.start))
            print('End Time: {:.6f} seconds'.format(c.end))

            print(
                'Duration: {:.6f} seconds'.format(
                    c.end - c.start
                )
            )

            print(
                'Number of packets sent from Source to Destination:',
                c.packets[0]
            )

            print(
                'Number of packets sent from Destination to Source:',
                c.packets[1]
            )

            print(
                'Total number of packets:',
                sum(c.packets)
            )

            print(
                'Number of data bytes sent from Source to Destination:',
                c.bytes[0]
            )

            print(
                'Number of data bytes sent from Destination to Source:',
                c.bytes[1]
            )

            print(
                'Total number of data bytes:',
                sum(c.bytes)
            )

        print('END')
        print('+' * 32)

    complete = [c for c in conns if c.complete]

    print('\nC) General\n')

    print(
        'Total number of complete TCP connections:',
        len(complete)
    )

    print(
        'Number of reset TCP connections:',
        sum(c.reset for c in conns)
    )

    print(
        'Number of TCP connections that were still open '
        'when the trace capture ended:',
        sum(c.is_open for c in conns)
    )

    print(
        'Number of TCP connections established before capture started:',
        sum(not c.first_was_syn for c in conns)
    )

    print('_' * 48)

    print('\nD) Complete TCP connections\n')

    def print_three(label, values, unit='', digits=6):
        result = stats(values)

        if result is None:
            print(label + ': N/A (no samples)')
            return

        names = ('Minimum', 'Mean', 'Maximum')

        for name, value in zip(names, result):
            print(
                '{} {}: {:.{}f}{}'.format(
                    name,
                    label,
                    value,
                    digits,
                    unit
                )
            )

    print_three(
        'time duration',
        [c.end - c.start for c in complete],
        ' seconds'
    )

    print()

    print_three(
        'RTT value',
        [r for c in complete for r in c.rtts()],
        ' seconds'
    )

    print()

    print_three(
        'number of packets including both send/received',
        [sum(c.packets) for c in complete],
        digits=4
    )

    print()

    print_three(
        'receive window size including both send/received',
        [w for c in complete for w in c.windows],
        ' bytes',
        4
    )

    print('_' * 48)


def main():
    # Get the capture filename from the command line
    if len(sys.argv) != 2:
        print(
            'Usage: python tcp_analysis.py <capture_file>',
            file=sys.stderr
        )
        return

    filename = sys.argv[1]

    try:
        connections = analyze(filename)

        # Automatically write results to the text file
        with open('analysis_output.txt', 'w') as output_file:
            original_stdout = sys.stdout

            try:
                sys.stdout = output_file
                report(connections)

            finally:
                sys.stdout = original_stdout

        # DEBUGGING:
        # Uncomment this line to print results in the terminal
        # report(connections)

        # Optional success message
        # print('Results saved to analysis_output.txt')

    except (OSError, ValueError) as error:
        print('Error:', error, file=sys.stderr)


if __name__ == '__main__':
    main()
