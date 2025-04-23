# Dylan Kenneth Eliot

"""
This creates dig compatible records that are likely also dns-sec compatible.

Enjoy

"""

import socket
import struct
import threading

# Configuration: zones and default TTL
default_ttl = 300
zones = {
    'example.com': {
        'A': ['192.0.2.1'],
        'AAAA': ['2001:db8::1'],
        'CNAME': ['alias.example.com'],
        'MX': [(10, 'mail.example.com')],
    },
    # Add more zones as needed
}

# DNS flags
FLAG_QR_RESPONSE = 0x8000
FLAG_AA = 0x0400
FLAG_TC = 0x0200
FLAG_RD = 0x0100
FLAG_RA = 0x0080

# QTYPE map
QTYPE = {
    1: 'A',
    28: 'AAAA',
    5: 'CNAME',
    15: 'MX',
}

# QCLASS
QCLASS_IN = 1


def decode_name(data, offset):
    labels = []
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:  # pointer
            pointer = struct.unpack_from('!H', data, offset)[0] & 0x3FFF
            part, _ = decode_name(data, pointer)
            labels.append(part)
            offset += 2
            break
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(data[offset:offset+length].decode())
        offset += length
    return '.'.join(labels), offset


def encode_name(name):
    parts = name.split('.')
    res = b''
    for part in parts:
        res += struct.pack('!B', len(part)) + part.encode()
    return res + b'\x00'


def build_response(data, tcp=False):
    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', data[:12])
    flags = FLAG_QR_RESPONSE | FLAG_AA
    # Preserve RD and set RA
    rd = struct.unpack('!H', data[2:4])[0] & FLAG_RD
    flags |= rd | FLAG_RA

    # Decode question
    offset = 12
    qname, offset = decode_name(data, offset)
    qtype, qclass = struct.unpack_from('!HH', data, offset)
    offset += 4

    answers = []
    zone = zones.get(qname)
    if zone and QTYPE.get(qtype) in zone:
        rtype = QTYPE[qtype]
        records = zone[rtype]
        # Handle CNAME chain first
        if rtype == 'CNAME':
            for target in records:
                answers.append((rtype, target))
            # After CNAME, look up A for target
            target = records[0]
            if 'A' in zone:
                for addr in zone['A']:
                    answers.append(('A', addr))
        elif rtype == 'MX':
            for preference, exchange in records:
                answers.append(('MX', (preference, exchange)))
        else:
            for addr in records:
                answers.append((rtype, addr))
        rcount = len(answers)
    else:
        # Name error
        flags |= 0x0003  # RCODE=3
        rcount = 0
    
    # Build header
    header = struct.pack('!HHHHHH', tid, flags, 1, rcount, 0, 0)
    question = data[12:offset]

    # Build answer RRs
    answer_bytes = b''
    for typ, val in answers:
        answer_bytes += b'\xc0\x0c'  # pointer to question name
        t = [k for k,v in QTYPE.items() if v == typ][0]
        answer_bytes += struct.pack('!HHI', t, QCLASS_IN, default_ttl)
        if typ == 'A':
            rdata = socket.inet_aton(val)
            answer_bytes += struct.pack('!H', len(rdata)) + rdata
        elif typ == 'AAAA':
            rdata = socket.inet_pton(socket.AF_INET6, val)
            answer_bytes += struct.pack('!H', len(rdata)) + rdata
        elif typ == 'CNAME':
            cname_encoded = encode_name(val)
            answer_bytes += struct.pack('!H', len(cname_encoded)) + cname_encoded
        elif typ == 'MX':
            pref, exch = val
            exch_enc = encode_name(exch)
            rdata = struct.pack('!H', pref) + exch_enc
            answer_bytes += struct.pack('!H', len(rdata)) + rdata

    response = header + question + answer_bytes

    # Truncate if UDP and too large
    if not tcp and len(response) > 512:
        # Set TC flag
        flags = struct.pack('!H', FLAG_QR_RESPONSE | FLAG_TC | rd | FLAG_AA | FLAG_RA)
        response = struct.pack('!HHHHHH', tid, FLAG_QR_RESPONSE | FLAG_TC | rd | FLAG_AA | FLAG_RA, 1, 0, 0, 0) + question
    return response


def handle_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 53))
    print('[*] UDP DNS server listening on port 53')
    while True:
        data, addr = sock.recvfrom(1024)
        response = build_response(data, tcp=False)
        sock.sendto(response, addr)


def handle_tcp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 53))
    sock.listen(5)
    print('[*] TCP DNS server listening on port 53')
    while True:
        conn, addr = sock.accept()
        data = conn.recv(2)
        if not data:
            conn.close()
            continue
        length = struct.unpack('!H', data)[0]
        query = conn.recv(length)
        response = build_response(query, tcp=True)
        # Prepend length for TCP
        conn.send(struct.pack('!H', len(response)) + response)
        conn.close()


def main():
    threading.Thread(target=handle_udp, daemon=True).start()
    threading.Thread(target=handle_tcp, daemon=True).start()
    print('[*] DNS server running (UDP & TCP). Press Ctrl+C to stop.')
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print('\n[!] Shutting down DNS server.')

if __name__ == '__main__':
    main()
