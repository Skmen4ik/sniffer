import socket
import struct
from datetime import datetime
from datetime import time as time_func
from traceback import format_exc

from config import white_list
from utils import tcp_check, icmp_check, get_my_ip, get_loger, icmp_bun, tcp_bun, update_list_time

my_ip = get_my_ip()
logs = get_loger()
data_sniffer = {
    'ICMP': {},
    'TCP': {}
}


def convert_byte_to_str(byte_mac):
    return ':'.join(map('{:02X}'.format, byte_mac))


def convert_ipv4(byte_ipv4):
    return '.'.join(map(str, byte_ipv4))


def unpack_ethernet_frame(frame):
    dest_mac, source_mac, protocol = struct.unpack('! 6s 6s H', frame[:14])
    return convert_byte_to_str(dest_mac), convert_byte_to_str(source_mac), socket.htons(protocol), frame[14:]


def unpack_ipv4(data):
    version = data[0] >> 4
    header_len = (data[0] & 15) * 4

    ttl, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, protocol, convert_ipv4(source), convert_ipv4(target), data[20:]


def unpack_icmp(data):
    icmp_type, code, summ = struct.unpack('! B B H', data[:4])
    return icmp_type, code, summ, data[4:]


def unpack_tcp(data):
    src_port, dest_port, sequence, acknowledment, offset_reserved_flag = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 16) >> 4
    flag_psh = (offset_reserved_flag & 8) >> 3
    flag_rst = (offset_reserved_flag & 4) >> 2
    flag_syn = (offset_reserved_flag & 2) >> 1
    flag_fin = offset_reserved_flag & 1
    flags = flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin
    return src_port, dest_port, sequence, acknowledment, flags, data[offset:]


def check_ipv4(source):
    if source == my_ip:
        return True

    if source in white_list:
        return True
    return False


def sniffer():
    logs['loger_all'].info(f'Начало работы {datetime.now()}')
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        packet = connection.recvfrom(65536)

        dest_mac, source_mac, protocol_ether, data_proto = unpack_ethernet_frame(packet[0])

        if protocol_ether == 8:
            version, header_len, ttl, protocol, source, target, data_ipv4 = unpack_ipv4(data_proto)
            #print(version, header_len, ttl, protocol, source, target, data_ipv4)
            if check_ipv4(source):
                continue

            # ICMP
            if protocol == 1:
                logs['loger_icmp'].info(f'{protocol_ether} {protocol} {source} {target}')
                print('ICMP', source, target)
                time_now = datetime.now()

                if data_sniffer['ICMP'].get(source):
                    data_sniffer['ICMP'][source].append(time_func(time_now.hour, time_now.minute))
                else:
                    data_sniffer['ICMP'][source] = [time_func(time_now.hour, time_now.minute)]

                data_sniffer['ICMP'][source] = update_list_time(data_sniffer['ICMP'][source],
                                                                time_func(time_now.hour - 1, time_now.minute))

                if icmp_check(version, header_len, ttl, protocol, source, target,
                              data_sniffer, logs['loger_icmp'], protocol_ether):
                    icmp_bun(version, header_len, ttl, protocol, source, target, data_sniffer, logs['loger_icmp'],
                             protocol_ether)

            # TCP
            if protocol == 6:
                logs['loger_tcp'].info(f'{protocol_ether} {protocol} {source} {target}')

                src_port, dest_port, sequence, acknowledment, flags_fin, data = unpack_tcp(data_ipv4)
                print('TCP', source, target, src_port, dest_port)

                if data_sniffer['TCP'].get(source):
                    if data_sniffer['TCP'][source].get(dest_port):
                        data_sniffer['TCP'][source][dest_port] += 1
                    else:
                        data_sniffer['TCP'][source][dest_port] = 1
                else:
                    data_sniffer['TCP'][source] = {dest_port: 1}

                if tcp_check(data_sniffer, source, logs['loger_tcp'], protocol_ether, protocol, target):
                    tcp_bun(data_sniffer, source, logs['loger_tcp'], protocol_ether, protocol, target)


try:
    sniffer()
except:
    logs['loger_all'].info(f'Прекращение работы {datetime.now()} {format_exc()}')
    logs['loger_all'].info(f'Data sniffer: {data_sniffer}')
