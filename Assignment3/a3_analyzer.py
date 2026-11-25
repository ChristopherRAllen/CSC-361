import struct
import sys


UDP_TRACE_PORT_MIN = 33434
UDP_TRACE_PORT_MAX = 33625
VLAN_ETHERTYPES = (0x8100, 0x88A8, 0x9100)


def read_pcap(path):
    with open(path, 'rb') as capture:
        magic = capture.read(4)
        # The magic value gives the byte order and timestamp precision.
        formats = {
            b'\xd4\xc3\xb2\xa1': ('<', 1000000),
            b'\xa1\xb2\xc3\xd4': ('>', 1000000),
            b'\x4d\x3c\xb2\xa1': ('<', 1000000000),
            b'\xa1\xb2\x3c\x4d': ('>', 1000000000),
        }

        if magic not in formats:
            raise ValueError('Unsupported capture file format')

        endian, fraction_divisor = formats[magic]
        global_header = capture.read(20)

        if len(global_header) != 20:
            raise ValueError('Invalid PCAP global header')

        values = struct.unpack(endian + 'HHiIII', global_header)
        if values[5] != 1:
            raise ValueError('Expected an Ethernet PCAP capture')

        first_timestamp = None
        while True:
            record_header = capture.read(16)
            if not record_header:
                break
            if len(record_header) != 16:
                raise ValueError('Incomplete PCAP packet header')

            seconds, fraction, captured_length, original_length = struct.unpack(
                endian + 'IIII', record_header
            )
            if captured_length > 100000000:
                raise ValueError('Invalid PCAP packet length')

            frame = capture.read(captured_length)
            if len(frame) != captured_length:
                raise ValueError('Incomplete PCAP packet data')

            timestamp = seconds + fraction / fraction_divisor
            if first_timestamp is None:
                first_timestamp = timestamp
            yield timestamp - first_timestamp, frame


def get_ip_address(data):
    if len(data) != 4:
        return None
    return '.'.join(str(value) for value in data)


def parse_ipv4_frame(frame):
    if len(frame) < 14:
        return None

    ethertype = struct.unpack_from('!H', frame, 12)[0]
    ip_start = 14
    # Skip VLAN tags until the IPv4 EtherType is found.
    while ethertype in VLAN_ETHERTYPES:
        if len(frame) < ip_start + 4:
            return None
        ethertype = struct.unpack_from('!H', frame, ip_start + 2)[0]
        ip_start += 4

    if ethertype != 0x0800 or len(frame) < ip_start + 20:
        return None

    version_ihl = frame[ip_start]
    version = version_ihl >> 4
    header_length = (version_ihl & 0x0F) * 4
    if version != 4 or header_length < 20:
        return None
    if len(frame) < ip_start + header_length:
        return None

    total_length = struct.unpack_from('!H', frame, ip_start + 2)[0]
    if total_length < header_length:
        return None

    fragment_field = struct.unpack_from('!H', frame, ip_start + 6)[0]
    packet_end = min(len(frame), ip_start + total_length)
    payload_start = ip_start + header_length

    return {
        'src': get_ip_address(frame[ip_start + 12:ip_start + 16]),
        'dst': get_ip_address(frame[ip_start + 16:ip_start + 20]),
        'protocol': frame[ip_start + 9],
        'ttl': frame[ip_start + 8],
        'identification': struct.unpack_from('!H', frame, ip_start + 4)[0],
        'flags': (fragment_field >> 13) & 0x07,
        'more_fragments': bool(fragment_field & 0x2000),
        'fragment_offset': (fragment_field & 0x1FFF) * 8,  # Fragment offsets use eight-byte units.
        'header_length': header_length,
        'total_length': total_length,
        'payload': frame[payload_start:packet_end],
        'captured_length': max(0, packet_end - payload_start),
        'truncated': packet_end < ip_start + total_length,
    }


def parse_transport(packet):
    result = dict(packet)
    result['udp'] = None
    result['icmp'] = None

    if packet['fragment_offset'] != 0:
        return result

    payload = packet['payload']
    if packet['protocol'] == 17:
        if len(payload) >= 8:
            source_port, destination_port, length, checksum = struct.unpack_from(
                '!HHHH', payload, 0
            )
            result['udp'] = {
                'src_port': source_port,
                'dst_port': destination_port,
                'length': length,
            }
    elif packet['protocol'] == 1:
        if len(payload) >= 8:
            icmp_type, code = struct.unpack_from('!BB', payload, 0)
            icmp = {'type': icmp_type, 'code': code}
            if icmp_type in (0, 8):
                icmp['identifier'], icmp['sequence'] = struct.unpack_from(
                    '!HH', payload, 4
                )
            elif icmp_type in (3, 11, 12):
                quoted = parse_quoted_ipv4(payload[8:])
                if quoted is not None:
                    icmp['quoted'] = quoted
            result['icmp'] = icmp

    return result


def parse_quoted_ipv4(data):
    if len(data) < 20:
        return None

    version_ihl = data[0]
    if version_ihl >> 4 != 4:
        return None
    header_length = (version_ihl & 0x0F) * 4
    if header_length < 20 or len(data) < header_length:
        return None

    quoted = {
        'src': get_ip_address(data[12:16]),
        'dst': get_ip_address(data[16:20]),
        'protocol': data[9],
        'ttl': data[8],
        'identification': struct.unpack_from('!H', data, 4)[0],
        'payload': data[header_length:],
    }
    payload = quoted['payload']
    if quoted['protocol'] == 17 and len(payload) >= 4:
        quoted['udp'] = {
            'src_port': struct.unpack_from('!H', payload, 0)[0],
            'dst_port': struct.unpack_from('!H', payload, 2)[0],
        }
    elif quoted['protocol'] == 1 and len(payload) >= 8:
        if payload[0] in (0, 8):
            quoted['icmp'] = {
                'type': payload[0],
                'identifier': struct.unpack_from('!H', payload, 4)[0],
                'sequence': struct.unpack_from('!H', payload, 6)[0],
            }
    return quoted


def is_udp_probe(packet):
    udp = packet.get('udp')
    return (
        packet['protocol'] == 17
        and packet['fragment_offset'] == 0
        and udp is not None
        and UDP_TRACE_PORT_MIN <= udp['dst_port'] <= UDP_TRACE_PORT_MAX
    )


def is_echo_probe(packet):
    icmp = packet.get('icmp')
    return (
        packet['protocol'] == 1
        and packet['fragment_offset'] == 0
        and icmp is not None
        and icmp['type'] == 8
    )


def datagram_key(packet):
    return (
        packet['src'], packet['dst'], packet['protocol'],
        packet['identification'], packet['ttl'],
    )


def summarize_fragments(datagrams):
    patterns = {}
    for datagram in datagrams.values():
        fragments = datagram['packets']
        is_fragmented = any(
            packet['more_fragments'] or packet['fragment_offset'] > 0
            for packet in fragments
        )
        if not is_fragmented:
            shape = (0, 0)
        else:
            count = len(fragments)
            last_offset = max(packet['fragment_offset'] for packet in fragments)
            shape = (count, last_offset)
        patterns.setdefault(shape, []).append(datagram['identification'])
    return patterns


def calculate_stats(values):
    if not values:
        return None
    average = sum(values) / len(values)
    if len(values) > 1:
        variance = sum((value - average) ** 2 for value in values) / (len(values) - 1)
        deviation = variance ** 0.5
    else:
        deviation = 0.0
    return average, deviation


def analyze(path):
    packets = []
    for timestamp, frame in read_pcap(path):
        packet = parse_ipv4_frame(frame)
        if packet is not None:
            packet['time'] = timestamp
            packets.append(parse_transport(packet))

    probes = [packet for packet in packets if is_udp_probe(packet) or is_echo_probe(packet)]
    if not probes:
        raise ValueError('No traceroute UDP or ICMP Echo probes were found')

    source_ip = probes[0]['src']
    destination_ip = probes[0]['dst']
    probes = [
        packet for packet in probes
        if packet['src'] == source_ip and packet['dst'] == destination_ip
    ]

    datagrams = {}
    probe_packet_ids = {id(packet) for packet in probes}
    for packet in packets:
        key = datagram_key(packet)
        if key not in datagrams:
            datagrams[key] = {
                'src': packet['src'],
                'dst': packet['dst'],
                'protocol': packet['protocol'],
                'identification': packet['identification'],
                'ttl': packet['ttl'],
                'packets': [],
                'first_packet': None,
                'response_records': [],
            }
        datagrams[key]['packets'].append(packet)

        if id(packet) in probe_packet_ids and datagrams[key]['first_packet'] is None:
            datagrams[key]['first_packet'] = packet

    source_datagrams = {
        key: datagram for key, datagram in datagrams.items()
        if datagram['first_packet'] is not None
    }
    if not source_datagrams:
        raise ValueError('Traceroute probes could not be grouped into datagrams')

    # Use the quoted transport fields for matching; some traces rewrite the IP ID.
    probe_index = {}
    for datagram in source_datagrams.values():
        first = datagram['first_packet']
        if first['protocol'] == 17:
            udp = first.get('udp')
            if udp is None:
                continue
            signature = (
                first['src'], first['dst'], 17,
                udp['src_port'], udp['dst_port'],
            )
        else:
            icmp = first.get('icmp')
            if icmp is None:
                continue
            signature = (
                first['src'], first['dst'], 1,
                icmp['identifier'], icmp['sequence'],
            )
        probe_index.setdefault(signature, []).append(datagram)

    responses_by_router = {}
    routers_by_ttl = {}
    rtts_by_ttl = {}
    destination_samples = []
    matched_responses = []

    for packet in packets:
        icmp = packet.get('icmp')
        if packet['protocol'] != 1 or icmp is None:
            continue

        matching_datagram = None
        response_kind = None
        if icmp['type'] in (3, 11, 12):
            quoted = icmp.get('quoted')
            if quoted is None:
                continue
            if quoted['protocol'] == 17 and quoted.get('udp') is not None:
                signature = (
                    quoted['src'], quoted['dst'], 17,
                    quoted['udp']['src_port'], quoted['udp']['dst_port'],
                )
            elif quoted['protocol'] == 1 and quoted.get('icmp') is not None:
                signature = (
                    quoted['src'], quoted['dst'], 1,
                    quoted['icmp']['identifier'], quoted['icmp']['sequence'],
                )
            else:
                continue
            candidates = [
                datagram for datagram in probe_index.get(signature, [])
                if datagram['first_packet']['time'] <= packet['time']
            ]
            if not candidates:
                continue
            matching_datagram = candidates[0]
            for candidate in candidates[1:]:
                candidate_time = candidate['first_packet']['time']
                matching_time = matching_datagram['first_packet']['time']
                if candidate_time > matching_time:
                    matching_datagram = candidate
            response_kind = 'ttl' if icmp['type'] == 11 else 'unreachable'
        elif icmp['type'] == 0:
            signature = (
                packet['dst'], packet['src'], 1,
                icmp['identifier'], icmp['sequence'],
            )
            candidates = [
                datagram for datagram in probe_index.get(signature, [])
                if datagram['first_packet']['time'] <= packet['time']
                and datagram['first_packet'].get('icmp', {}).get('type') == 8
            ]
            if candidates:
                matching_datagram = candidates[0]
                for candidate in candidates[1:]:
                    candidate_time = candidate['first_packet']['time']
                    matching_time = matching_datagram['first_packet']['time']
                    if candidate_time > matching_time:
                        matching_datagram = candidate
                response_kind = 'echo_reply'

        if matching_datagram is None:
            continue

        response_record = {
            'time': packet['time'],
            'router': packet['src'],
            'ttl': matching_datagram['ttl'],
            'kind': response_kind,
        }
        matching_datagram['response_records'].append(response_record)
        matched_responses.append(response_record)

        # One ICMP error can provide an RTT sample for every fragment.
        sent_times = [fragment['time'] for fragment in matching_datagram['packets']]
        rtts = [packet['time'] - sent_time for sent_time in sent_times]
        if response_kind == 'ttl':
            router = packet['src']
            responses_by_router.setdefault(router, []).extend(rtts)
            ttl_routers = routers_by_ttl.setdefault(matching_datagram['ttl'], [])
            if router not in ttl_routers:
                ttl_routers.append(router)
            rtts_by_ttl.setdefault(matching_datagram['ttl'], []).extend(rtts)
        elif packet['src'] == destination_ip:
            destination_samples.extend(rtts)
            rtts_by_ttl.setdefault(matching_datagram['ttl'], []).extend(rtts)

    protocols = {packet['protocol'] for packet in probes}
    if matched_responses:
        protocols.add(1)

    return {
        'source': source_ip,
        'destination': destination_ip,
        'datagrams': source_datagrams,
        'routers_by_ttl': routers_by_ttl,
        'rtts_by_ttl': rtts_by_ttl,
        'router_rtts': responses_by_router,
        'destination_rtts': destination_samples,
        'protocols': sorted(protocols),
        'fragment_patterns': summarize_fragments(source_datagrams),
        'matched_responses': matched_responses,
    }


def format_protocol(protocol):
    names = {1: 'ICMP', 17: 'UDP'}
    return '{}: {}'.format(protocol, names.get(protocol, 'Unknown'))


def report(result, output):
    print('The IP address of the source node: {}'.format(result['source']), file=output)
    print('The IP address of ultimate destination node: {}'.format(
        result['destination']), file=output)
    print('The IP addresses of the intermediate destination nodes:', file=output)

    if not result['routers_by_ttl']:
        print('No intermediate routers responded.', file=output)
    else:
        for ttl in sorted(result['routers_by_ttl']):
            for router in result['routers_by_ttl'][ttl]:
                print('router {}: {},'.format(ttl, router), file=output)

    print('\nThe values in the protocol field of IP headers:', file=output)
    for protocol in result['protocols']:
        print(format_protocol(protocol), file=output)

    print('', file=output)
    pattern_items = list(result['fragment_patterns'].items())
    for index, ((count, offset), identifications) in enumerate(pattern_items, 1):
        if len(pattern_items) == 1:
            suffix = ''
        else:
            suffix = ' (fragmentation pattern {}; IP ID values: {})'.format(
                index, ', '.join(str(value) for value in identifications[:8])
            )
            if len(identifications) > 8:
                suffix += ', ...'
        print('The number of fragments created from the original datagram{} is: {}'.format(
            suffix, count), file=output)
        print('The offset of the last fragment is: {}'.format(offset), file=output)
        if index != len(pattern_items):
            print('', file=output)

    print('', file=output)
    ordered_routers = []
    for ttl in sorted(result['routers_by_ttl']):
        for router in result['routers_by_ttl'][ttl]:
            if router not in ordered_routers:
                ordered_routers.append(router)

    for router in ordered_routers:
        values = result['router_rtts'].get(router, [])
        stats = calculate_stats(values)
        if stats is None:
            print('The avg RTT between {} and {} is: N/A, the s.d. is: N/A'.format(
                result['source'], router), file=output)
        else:
            average, deviation = stats
            print('The avg RTT between {} and {} is: {:.3f} ms, the s.d. is: {:.3f} ms ({} samples)'.format(
                result['source'], router, average * 1000, deviation * 1000,
                len(values)), file=output)

    stats = calculate_stats(result['destination_rtts'])
    if stats is None:
        print('The avg RTT between {} and {} is: N/A, the s.d. is: N/A'.format(
            result['source'], result['destination']), file=output)
    else:
        average, deviation = stats
        print('The avg RTT between {} and {} is: {:.3f} ms, the s.d. is: {:.3f} ms ({} samples)'.format(
            result['source'], result['destination'], average * 1000,
            deviation * 1000, len(result['destination_rtts'])), file=output)


def main():
    if len(sys.argv) not in (2, 4) or (len(sys.argv) == 4 and sys.argv[2] != '-o'):
        print(
            'Usage: python3 a3_analyzer.py <capture.pcap> [-o output.txt]',
            file=sys.stderr,
        )
        return 1

    filename = sys.argv[1]
    output_path = sys.argv[3] if len(sys.argv) == 4 else 'analysis_output.txt'
    try:
        result = analyze(filename)
        with open(output_path, 'w', encoding='utf-8') as output:
            report(result, output)
        print('Analysis written to {}'.format(output_path))
    except (OSError, ValueError, struct.error) as error:
        print('Error: {}'.format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
