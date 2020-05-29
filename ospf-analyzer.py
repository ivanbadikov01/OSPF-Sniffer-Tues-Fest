import socket
import struct

def create():
        MCAST_GROUP = "224.0.0.5"
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, 89)
        mreq = struct.pack('4sL', socket.inet_aton(MCAST_GROUP), socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        return s

def unpack_ospf_header(data):
    return struct.unpack("!BBH4s4sHH4s4s", data)

def unpack_hello_message(data, neighbours):
    neigh_format = "!" + ("4s" * int((len(neighbours)/4)))
    return {
        'payload' : struct.unpack("!4sHBBL4s4s", data), 
        'neighbours' : struct.unpack(neigh_format, neighbours)
    }

def unpack_lsa_header(data):
    return struct.unpack("!HxB4s4sIHH", data)

def unpack_router_lsa(data):
    links_num = struct.unpack("!H", data[2:4])[0]
    unpack_format = "!4x" + "4s4sBBH" * links_num
    return (
        struct.unpack(unpack_format, data),
        links_num
    )

def unpack_network_lsa(data, length):
    unpack_format = "!" + ("4s" * int(length/4))
    return struct.unpack(unpack_format, data)

def unpack_summary_lsa(data):
    return (
        struct.unpack("!4sB", data[0:5]),
        unpack_three_bytes(data[5:8])
    )

def unpack_three_bytes(data):
    metric = bytearray(b'\x00')
    metric.extend(struct.pack(">3b", data[0], data[1], data[2]))
    return struct.unpack(">I", metric)[0]

def unpack_external_lsa(data):
    return (
        struct.unpack('!4s4x4sI', data),
        unpack_three_bytes(data[5:8])
    )

def unpack_dbd_packet(data):
    return struct.unpack('!HBxI', data)

def unpack_request_packet(data):
    unpack_format = "!" + "I4s4s" * int(len(data) / 8)
    return struct.unpack(unpack_format, data)

def decode_header(data):
    return {
        'version' : data[0],
        'message_type' : data[1],
        'length' : data[2],
        'router_id' : socket.inet_ntoa(data[3]),
        'area_id' : socket.inet_ntoa(data[4]),
        'checksum' : hex(data[5]),
        'autype' : data[6]
    }

def print_header(fields):
    Message_type = get_message_type(fields['message_type'])
    print("=" * 30 + f"{Message_type}" + "=" * 30)
    print(f"Version: {fields['version']}")
    print(f"Length: {fields['length']}")
    print(f"Router-id: {fields['router_id']}")
    print(f"Area: {fields['area_id']}")
    print(f"Checksum: {fields['checksum']}")
    print(f"AuType: {fields['autype']}")

def get_message_type(id):
    return {
        1 : 'Hello',
        2 : 'Database Description',
        3 : 'Request',
        4 : 'Update',
        5 : 'Acknowledgement'
    }.get(id)

def decode_hello_message(data, neighbours):
    return (
        {
        'network_mask' : socket.inet_ntoa(data[0]),
        'hello_interval' : data[1],
        'rtr_priority' : data[3],
        'dead_interval' : data[4],
        'designated_router' : socket.inet_ntoa(data[5]),
        'backup_designated_router' : socket.inet_ntoa(data[6])
    }, list(map(socket.inet_ntoa, neighbours))
    )

def print_hello_message(fields, neighbours):
    neighbours_string = ', '.join(neighbours)
    print(f"Network mask: {fields['network_mask']}")
    print(f"Hello interval: {fields['hello_interval']}")
    print(f"Router priority: {fields['rtr_priority']}")
    print(f"Dead interval: {fields['dead_interval']}")
    print(f"Designated router: {fields['designated_router']}")
    print(f"Backup Designated router: {fields['backup_designated_router']}")
    print(f"Neighbours: {neighbours_string}")

def handle_hello_message(data):

        binary_ospf_payload = data[0:20]

        binary_ospf_neighbours = data[20:len(data)]        
        
        unpacked_payload = unpack_hello_message(binary_ospf_payload, binary_ospf_neighbours)

        decoded_payload, decoded_neighbours = decode_hello_message(unpacked_payload["payload"], unpacked_payload["neighbours"])
        print_hello_message(decoded_payload, decoded_neighbours)

def decode_lsa_header(data):
    return {
        'ls_age': data[0],
        'type': data[1],
        'link_id': socket.inet_ntoa(data[2]),
        'adv_router': socket.inet_ntoa(data[3]),
        'sequence_num': hex(data[4]),
        'checksum': hex(data[5]),
        'length': data[6]
    }

def print_lsa_header(data):
    print(f"LS age: {data['ls_age']}")
    print(f"LSA Type: {data['type']}")
    print(f"Link State ID: {data['link_id']}")
    print(f"Advertising Router: {data['adv_router']}")
    print(f"Sequence number: {data['sequence_num']}")
    print(f"Checksum: {data['checksum']}")
    print(f"Length: {data['length']}")

def decode_router_lsa(data):
    num_links = data[1]
    links = list()

    for i in range (0, num_links):
        element = list()
        for j in range (0, 5):
            element.append(data[0][j])
        links.append(element)

    return links

def handle_multiple_lsa_headers(data):
    lsa_index = 1
    for i in range(0, len(data), 20):
        print(f"-" * 20 + f"LSA #{lsa_index}" + f"-" * 20)
        lsa_header = unpack_lsa_header(data[i:i+20])
        decoded_lsa_header = decode_lsa_header(lsa_header)
        print_lsa_header(decoded_lsa_header)
        lsa_index = lsa_index + 1

def handle_single_lsa_header(data):
    unpacked_header = unpack_lsa_header(data)
    return decode_lsa_header(unpacked_header)

def print_router_lsa(data):
    i = 1
    for link in data:
        print('-' * 30 + f"Link #{i}" + '-' * 30) 
        print(f"Link ID: {socket.inet_ntoa(link[0])}")
        print(f"Link data: {socket.inet_ntoa(link[1])}")
        print(f"Type: {link[2]}")
        print(f"TOS: {link[3]}")
        print(f"Metric: {link[4]}")
        i = i+1

def handle_router_lsa(data):
    header = handle_single_lsa_header(data[0:20])
    payload = data[20:len(data)]

    unpacked_payload = unpack_router_lsa(payload)
    decoded_payload = decode_router_lsa(unpacked_payload)

    print_lsa_header(header)
    print_router_lsa(decoded_payload)

def decode_network_lsa(data):
    return {
        "net_mask": socket.inet_ntoa(data[0]),
        "attached_routers": list(map(socket.inet_ntoa, data[1:len(data)]))

    }

def print_network_lsa(data):
    attached_routers = ', '.join(data['attached_routers'])
    print(f"Network mask: {data['net_mask']}")
    print(f"Attached routers: {attached_routers}")

def handle_network_lsa(data):
    header = handle_single_lsa_header(data[0:20])
    payload = data[20:len(data)]

    unpacked_payload = unpack_network_lsa(payload, (header['length']-20))
    decoded_payload = decode_network_lsa(unpacked_payload)
    print_lsa_header(header)
    print_network_lsa(decoded_payload)

def decode_summary_lsa(data):
    return {
        "net_mask": socket.inet_ntoa(data[0][0]),
        "tos": data[0][1],
        "metric": data[1]
    }

def print_summary_lsa(data):
    print(f"Network mask: {data['net_mask']}")
    print(f"TOS: {data['tos']}")
    print(f"Metric: {data['metric']}")

def handle_summary_lsa(data):
    header = handle_single_lsa_header(data[0:20])
    payload = data[20:len(data)]

    unpacked_payload = unpack_summary_lsa(payload)
    decoded_payload = decode_summary_lsa(unpacked_payload)
    
    print_lsa_header(header)

    print_summary_lsa(decoded_payload)

def decode_external_lsa(data, metric):
    return {
        'net_mask': socket.inet_ntoa(data[0]),
        'fwd_addr': socket.inet_ntoa(data[1]),
        'ext_tag': data[2],
        'metric': metric
    }

def print_external_lsa(data):
    print(f"Network Mask: {data['net_mask']}")
    print(f"Metric: {data['metric']}")
    print(f"Forwarding address: {data['fwd_addr']}")
    print(f"External Route Tag: {data['ext_tag']}")

def handle_external_lsa(data):
    header = handle_single_lsa_header(data[0:20])
    payload = data[20:len(data)]

    unpacked_payload, metric = unpack_external_lsa(payload)
    decoded_payload = decode_external_lsa(unpacked_payload, metric)

    print_lsa_header(header)
    print_external_lsa(decoded_payload)

def handle_update_packet(data):
    lsa_num = struct.unpack("!I", data[0:4])[0]
    lsa_start = 4
    for i in range(0, lsa_num):
        lsa_header = handle_single_lsa_header(data[lsa_start:lsa_start+20])

        print('-' * 30 + f"Lsa #{i+1}" + '-' * 30) 
        if lsa_header['type'] == 1:
            handle_router_lsa(data[lsa_start:lsa_start+lsa_header['length']])
        elif lsa_header['type'] == 2:
            handle_network_lsa(data[lsa_start:lsa_start+lsa_header['length']])
        elif lsa_header['type'] == 3 or lsa_header['type'] == 4:
            handle_summary_lsa(data[lsa_start:lsa_start+lsa_header['length']])
        elif lsa_header['type'] == 5:
            handle_external_lsa(data[lsa_start:lsa_start+lsa_header['length']])
        
        lsa_start += lsa_header['length']

def decode_dbd_packet(data):
    return {
        'mtu': data[0],
        'options': data[1],
        'sequence_num': hex(data[2])
    }

def print_dbd_packet(data):
    print(f"Interface MTU: {data['mtu']}")
    print(f"Options: {data['options']}")
    print(f"Sequence number: {data['sequence_num']}")

def handle_dbd_packet(data):
    info = unpack_dbd_packet(data[:8])
    decoded_info = decode_dbd_packet(info)
    print_dbd_packet(decoded_info)
    
    handle_multiple_lsa_headers(data[8:])

def decode_request_packet(data):
    lsas = list()
    for i in range(0, len(data), 3):
        lsas.append({
            'ls_type': data[i],
            'link_id': socket.inet_ntoa(data[i+1]),
            'adv_router': socket.inet_ntoa(data[i+2])
        })
    return lsas

def print_request_packet(data):
    i = 1;
    for lsa in data:
        print('-' * 30 + f"Lsa #{i}" + '-' * 30) 
        print(f"LS type: {lsa['ls_type']}")
        print(f"Link State ID: {lsa['link_id']}")
        print(f"Advertising Router: {lsa['adv_router']}")
        i = i+1

def handle_request_packet(data):
    unpacked_data = unpack_request_packet(data)
    decoded_data = decode_request_packet(unpacked_data)
    print_request_packet(decoded_data)

def handle_ospf_header(data):
    unpacked_header = unpack_ospf_header(data)

    decoded_header = decode_header(unpacked_header)

    print_header(decoded_header)

def get_message_type_from_header(data):
    return decode_header(unpack_ospf_header(data))['message_type']

print("/"*15 + "---OSPFv2 Analyzer Made by Ivan Badikov---" + "\\"*15)

while True:
    try:
        s = create()
        
        data = s.recv(65535)

        ospf = data[20:len(data)]

        ospf_header = ospf[0:24]

        ospf_payload = ospf[24:len(ospf)]
        
        handle_ospf_header(ospf_header)

        message_type = get_message_type_from_header(ospf_header) 

        if message_type == 1:
            handle_hello_message(ospf_payload)
        elif message_type == 2:
            handle_dbd_packet(ospf_payload)
        elif message_type == 3:
            handle_request_packet(ospf_payload)
        elif message_type == 4:
            handle_update_packet(ospf_payload)
        elif message_type == 5:
            handle_multiple_lsa_headers(ospf_payload)

    except KeyboardInterrupt:
        print("\n")
        exit(0)