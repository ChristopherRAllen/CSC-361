import os
import sys

import a3_analyzer


BASE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
TRACE_DIRECTORY = os.path.join(
    BASE_DIRECTORY, 'PcapTracesAssignment3'
)


def trace_path(directory, group_number, trace_number):
    filename = 'group{}-trace{}.pcap'.format(group_number, trace_number)
    return os.path.join(directory, filename)


def analyze_trace(path):
    result = a3_analyzer.analyze(path)
    probe_counts = {}
    for datagram in result['datagrams'].values():
        ttl = datagram['ttl']
        probe_counts[ttl] = probe_counts.get(ttl, 0) + 1

    route = []
    for ttl in sorted(result['routers_by_ttl']):
        for router in result['routers_by_ttl'][ttl]:
            route.append((ttl, router))

    return {
        'path': path,
        'result': result,
        'probe_counts': probe_counts,
        'route': route,
    }


def analyze_groups(directory=TRACE_DIRECTORY):
    groups = []
    for group_number in (1, 2):
        traces = [
            analyze_trace(trace_path(directory, group_number, trace_number))
            for trace_number in range(1, 6)
        ]
        # Response order within a TTL does not change the route comparison.
        route_signatures = [
            tuple((ttl, frozenset(route_at_ttl(trace, ttl)))
                  for ttl in sorted({hop for hop, address in trace['route']}))
            for trace in traces
        ]
        routes_match = all(route == route_signatures[0] for route in route_signatures[1:])
        maximum_ttl = max(
            [0]
            + [max(trace['probe_counts'], default=0) for trace in traces]
            + [max(trace['result']['routers_by_ttl'], default=0) for trace in traces]
        )
        hop_averages = {}
        for ttl in range(1, maximum_ttl + 1):
            per_trace = []
            for trace in traces:
                samples = trace['result']['rtts_by_ttl'].get(ttl, [])
                per_trace.append(
                    sum(samples) / len(samples) * 1000 if samples else None
                )
            if any(value is not None for value in per_trace):
                hop_averages[ttl] = per_trace

        groups.append({
            'number': group_number,
            'destination': traces[0]['result']['destination'],
            'traces': traces,
            'routes_match': routes_match,
            'maximum_ttl': maximum_ttl,
            'hop_averages': hop_averages,
        })
    return groups


def route_at_ttl(trace, ttl):
    return [router for hop, router in trace['route'] if hop == ttl]


def maximum_delay_hop(group):
    averages = group['hop_averages']
    means = []
    for ttl, values in averages.items():
        present = [value for value in values if value is not None]
        if present:
            means.append((ttl, sum(present) / len(present)))

    largest = None
    previous = None
    for ttl, average in means:
        if previous is not None:
            increase = average - previous[1]
            if largest is None or increase > largest[1]:
                largest = (ttl, increase)
        previous = (ttl, average)
    return largest


def format_ms(value):
    return 'N/A' if value is None else '{:.3f}'.format(value)


def print_report(groups, output=sys.stdout):
    for group in groups:
        print('GROUP {}'.format(group['number']), file=output)
        print('Destination: {}'.format(group['destination']), file=output)
        print('Probes per TTL:', file=output)
        all_ttls = sorted(set(
            ttl for trace in group['traces'] for ttl in trace['probe_counts']
        ))
        print('Trace | ' + ' | '.join('TTL {}'.format(ttl) for ttl in all_ttls), file=output)
        for index, trace in enumerate(group['traces'], 1):
            counts = [str(trace['probe_counts'].get(ttl, 0)) for ttl in all_ttls]
            print('{} | {}'.format(index, ' | '.join(counts)), file=output)

        if group['routes_match']:
            print('Router sequences: same in all five traces.', file=output)
            print('Per-hop average RTT (ms):', file=output)
            print('TTL | ' + ' | '.join('Trace {}'.format(i) for i in range(1, 6)), file=output)
            for ttl, values in group['hop_averages'].items():
                print('{} | {}'.format(
                    ttl, ' | '.join(format_ms(value) for value in values)
                ), file=output)
            delay = maximum_delay_hop(group)
            if delay is None:
                print('The traces do not provide enough consecutive RTTs to estimate an added-delay hop.', file=output)
            else:
                print('Largest increase in mean cumulative RTT: TTL {} ({:.3f} ms).'.format(
                    delay[0], delay[1]), file=output)
                print('This is an estimate from the increase between successive hop RTTs; return paths and router response delays can add noise.', file=output)
        else:
            print('Router sequences: differ across the five traces.', file=output)
            print('TTL | ' + ' | '.join('Trace {}'.format(i) for i in range(1, 6)), file=output)
            for ttl in range(1, group['maximum_ttl'] + 1):
                values = [', '.join(route_at_ttl(trace, ttl)) or 'no response'
                          for trace in group['traces']]
                router_sets = [set(route_at_ttl(trace, ttl)) for trace in group['traces']]
                if any(routers != router_sets[0] for routers in router_sets[1:]):
                    print('{} | {}'.format(ttl, ' | '.join(values)), file=output)
            print('Different routers for probes with the same TTL are consistent with load balancing: routers may choose paths using probe fields such as ports or flow identifiers.', file=output)
        print('', file=output)


def main():
    directory = TRACE_DIRECTORY
    text_path = 'r2_analysis_output.txt'
    arguments = iter(sys.argv[1:])
    for argument in arguments:
        if argument == '--traces':
            directory = next(arguments, None)
            if not directory:
                print('Error: --traces requires a directory', file=sys.stderr)
                return 1
        elif argument == '--text':
            text_path = next(arguments, None)
            if not text_path:
                print('Error: --text requires an output filename', file=sys.stderr)
                return 1
        else:
            print(
                'Usage: python3 r2_analysis.py [--traces directory] [--text output.txt]',
                file=sys.stderr,
            )
            return 1

    try:
        groups = analyze_groups(directory)
        with open(text_path, 'w', encoding='utf-8') as output:
            print_report(groups, output)
        print('R2 analysis written to {}'.format(text_path))
    except (OSError, ValueError, RuntimeError) as error:
        print('Error: {}'.format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
