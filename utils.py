import logging
from os import system
from socket import socket, AF_INET, SOCK_DGRAM

from config import url, chat_id

from requests import post


def get_loger():
    """Функция создает 3 обьекта класса логер, настраивает их и возращает словарь, где ключом выступает имя логера,
    а значением сам логер. Функция нужна для удобного сбора информации во время работы"""
    logger = {}
    # настройка логера под все
    loger_all = logging.getLogger('loger_all')

    loger_all.setLevel(logging.INFO)
    loger_all_handler = logging.FileHandler("loger_all.log", mode='w')
    loger_all_formatter = logging.Formatter("%(levelname)s %(asctime)s %(message)s")
    loger_all_handler.setFormatter(loger_all_formatter)
    loger_all.addHandler(loger_all_handler)

    # настройка логера под tcp
    loger_tcp = logging.getLogger('loger_tcp')

    loger_tcp.setLevel(logging.INFO)
    loger_tcp_handler = logging.FileHandler("loger_tcp.log", mode='w')
    loger_tcp_formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    loger_tcp_handler.setFormatter(loger_tcp_formatter)
    loger_tcp.addHandler(loger_tcp_handler)

    # настройка логера под icmp
    loger_icmp = logging.getLogger('loger_icmp')

    loger_icmp.setLevel(logging.INFO)
    loger_icmp_handler = logging.FileHandler("loger_icmp.log", mode='w')
    loger_icmp_formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    loger_icmp_handler.setFormatter(loger_icmp_formatter)
    loger_icmp.addHandler(loger_icmp_handler)

    # создаем словарь для удобного логирования
    logger['loger_all'] = loger_all
    logger['loger_icmp'] = loger_icmp
    logger['loger_tcp'] = loger_tcp

    return logger


def update_list_time(updating_list, time_min):
    index = 0
    for time in updating_list:
        if time > time_min:
            return updating_list[index:]

        index += 1
    return updating_list


def get_my_ip():
    st = socket(AF_INET, SOCK_DGRAM)
    ip = None
    try:
        st.connect(('10.255.255.255', 1))
        ip = st.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        st.close()
        return ip


def send_message_tg(text):
    param = {
        'text': text,
        'chat_id': chat_id
    }
    r = post(url, param)
    if r.status_code != 200:
        print(r.content)


def icmp_bun(version, header_len, ttl, protocol, source, target, data_sniffer, loger, protocol_ether):
    loger.warning(f'{protocol_ether} {protocol} {source} {target} BANING, ICMP spam')
    print(f'{protocol_ether} {protocol} {source} {target} BANING, ICMP spam')
    system(f'sudo iptables -t filter -A INPUT -s {source} -j DROP')
    data_sniffer['ICMP'].pop(source)
    send_message_tg(f'{protocol_ether} {protocol} {source} {target} BANING, ICMP spam')


def tcp_bun(source_data, source, loger, protocol_ether, protocol, target):
    loger.warning(f'{protocol_ether} {protocol} {source} {target} BANING, TCP spam')
    print(f'{protocol_ether} {protocol} {source} {target} BANING, TCP spam')
    system(f'sudo iptables -t filter -A INPUT -s {source} -j DROP')
    source_data['TCP'].pop(source)
    send_message_tg(f'{protocol_ether} {protocol} {source} {target} BANING, TCP spam')


def icmp_check(version, header_len, ttl, protocol, source, target, data_sniffer, loger, protocol_ether):
    if len(data_sniffer['ICMP'][source]) > 10:
        return True
    return False


def tcp_check(source_data, source, loger, protocol_ether, protocol, target):
    if len(source_data['TCP'][source]) > 10:
        return True
    return False

