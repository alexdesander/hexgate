#!/usr/bin/env python3
import argparse
import array
import collections
import fcntl
import heapq
import json
import os
import pathlib
import select
import signal
import socket
import struct
import subprocess
import sys
import time


def endpoint(args):
    control = socket.socket(fileno=int(args[0]))
    role, binary, ip, peer, start, warmup, duration, drain, cc, output = args[1:]
    tun = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
    fcntl.ioctl(tun, 0x400454CA, struct.pack('16sH', b'hg-tun', 0x1001))
    subprocess.run(['ip', 'address', 'add', ip + '/24', 'dev', 'hg-tun'], check=True)
    subprocess.run(['ip', 'link', 'set', 'hg-tun', 'mtu', '1400', 'up'], check=True)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    control.sendmsg([b'R'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [tun]))])
    address = ip if role == 'server' else peer
    result = subprocess.run([binary, role, address, start, warmup, duration, drain, cc, output])
    os.close(tun)
    raise SystemExit(result.returncode)


def isolated():
    mappings = pathlib.Path('/proc/self/uid_map').read_text().splitlines()
    if len(mappings) != 1 or mappings[0].split()[0] != '0' or mappings[0].split()[2] != '1':
        raise RuntimeError('Run inside unshare --user --map-root-user --net')
    interfaces = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show']))
    if [interface['ifname'] for interface in interfaces] != ['lo']:
        raise RuntimeError('Expected a fresh network namespace containing only loopback')


def receive_fd(control):
    control.settimeout(10)
    _, ancillary, _, _ = control.recvmsg(1, socket.CMSG_SPACE(array.array('i').itemsize))
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors = array.array('i')
            descriptors.frombytes(data[:descriptors.itemsize])
            return descriptors[0]
    raise RuntimeError('Endpoint did not return its TUN descriptor')


def scenario(args, cc):
    start_us = time.time_ns() // 1000 + 2_000_000
    prefix = args.out / cc
    prefix.mkdir(parents=True, exist_ok=True)
    processes, descriptors, controls = [], [], []
    try:
        for role, ip, peer in [('server', '10.77.0.2', '10.77.0.1'), ('client', '10.77.0.1', '10.77.0.2')]:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            controls.extend([parent, child])
            command = ['unshare', '--net', sys.executable, str(pathlib.Path(__file__).resolve()), 'endpoint',
                       str(child.fileno()), role, str(args.binary), ip, peer, str(start_us),
                       str(int(args.warmup * 1e6)), str(int(args.duration * 1e6)),
                       str(int(args.drain * 1e6)), cc, str(prefix / (role + '.json'))]
            processes.append(subprocess.Popen(command, pass_fds=[child.fileno()], start_new_session=True))
            child.close()
            descriptors.append(receive_fd(parent))
            parent.close()
        pending = []
        serial = [collections.deque(), collections.deque()]
        free_at = [0.0, 0.0]
        counts = [{'offered': 0, 'dropped': 0, 'delivered': 0, 'max_packet_bytes': 0,
                   'max_waiting_bytes': 0} for _ in descriptors]
        sequence = 0
        deadline = time.monotonic() + args.duration + args.drain + 7
        while any(process.poll() is None for process in processes):
            now = time.monotonic()
            if now > deadline:
                raise RuntimeError('Endpoint exceeded the experiment deadline')
            while pending and pending[0][0] <= now:
                _, _, source, packet = heapq.heappop(pending)
                try:
                    os.write(descriptors[source ^ 1], packet)
                    counts[source]['delivered'] += 1
                except BlockingIOError:
                    counts[source]['dropped'] += 1
            wait = min(0.01, max(0.0, pending[0][0] - now)) if pending else 0.01
            readable, _, _ = select.select(descriptors, [], [], wait)
            for descriptor in readable:
                source = descriptors.index(descriptor)
                for _ in range(128):
                    try:
                        packet = os.read(descriptor, 65536)
                    except BlockingIOError:
                        break
                    now = time.monotonic()
                    size = len(packet)
                    stats = counts[source]
                    stats['offered'] += 1
                    stats['max_packet_bytes'] = max(stats['max_packet_bytes'], size)
                    if size > 1400:
                        raise RuntimeError('TUN returned an unsegmented offloaded packet')
                    while serial[source] and serial[source][0][0] <= now:
                        serial[source].popleft()
                    waiting = sum(entry[1] for entry in serial[source])
                    if free_at[source] > now and waiting + size > args.queue_bytes:
                        stats['dropped'] += 1
                        continue
                    begin = max(now, free_at[source])
                    finish = begin + size / args.rate
                    free_at[source] = finish
                    if begin > now:
                        serial[source].append((begin, size))
                        waiting += size
                    stats['max_waiting_bytes'] = max(stats['max_waiting_bytes'], waiting)
                    sequence += 1
                    heapq.heappush(pending, (finish + args.delay_ms / 1000, sequence, source, packet))
        for process in processes:
            if process.wait() != 0:
                raise RuntimeError('Endpoint benchmark failed')
        client = json.loads((prefix / 'client.json').read_text())
        server = json.loads((prefix / 'server.json').read_text())
        result = {'tcp_controller': cc, 'bottleneck': {'rate_ip_bytes_per_second': args.rate,
                  'one_way_delay_ms': args.delay_ms, 'waiting_queue_bytes': args.queue_bytes},
                  'bridge': counts, 'client': client, 'server': server}
        result['snapshot_missing_after_drain'] = client['admitted'][0] - server['received'][0]
        result['urgent_missing_after_drain'] = client['admitted'][1] - server['received'][1]
        (prefix / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        return result
    finally:
        for process in processes:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        for process in processes:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        for descriptor in descriptors:
            os.close(descriptor)
        for control in controls:
            control.close()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'endpoint':
        endpoint(sys.argv[2:])
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    parser.add_argument('--tcp', default='none,cubic')
    parser.add_argument('--duration', type=float, default=15)
    parser.add_argument('--warmup', type=float, default=3)
    parser.add_argument('--drain', type=float, default=2)
    parser.add_argument('--rate', type=int, default=1_000_000)
    parser.add_argument('--delay-ms', type=float, default=20)
    parser.add_argument('--queue-bytes', type=int, default=65_536)
    args = parser.parse_args()
    if not (0 <= args.warmup < args.duration <= 300 and 0 <= args.drain <= 30
            and args.rate > 0 and args.queue_bytes >= 1400 and args.delay_ms >= 0):
        parser.error('invalid measurement interval or bottleneck configuration')
    args.binary = args.binary.resolve(strict=True)
    args.out = args.out.resolve()
    isolated()
    available = pathlib.Path('/proc/sys/net/ipv4/tcp_available_congestion_control').read_text().split()
    unavailable = set(args.tcp.split(',')) - set(available) - {'none'}
    if unavailable:
        raise RuntimeError(f'Kernel TCP controllers unavailable: {sorted(unavailable)}; available: {available}')
    results = [scenario(args, cc) for cc in args.tcp.split(',')]
    (args.out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
