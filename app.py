#!/usr/bin/env python3.8
# EX: ./app.py --ip 10.0.0.2 --password pass3 --console pass1 --timeout 1 --port 23

import argparse
from termcolor import cprint
from telnetlib import Telnet

def telnet_connection(ip, telnet_passwd, console_passwd=None, port=23):
    conn = Telnet(ip, port)
    conn.read_until(b'Password: ')
    conn.write(str.encode(telnet_passwd + '\n'))
    conn.write(b'enable\n')
    if console_passwd:
        conn.read_until(b'Password: ')
        conn.write(str.encode(console_passwd + '\n'))
    return conn



def read_all(connection, command, timeout=1):
    connection.write(str.encode(command))
    resp = connection.read_until(b'FINAL_INEXISTENT', timeout=timeout)
    while resp.endswith(b'--More-- '):
        connection.write(b' ')
        resp += connection.read_until(b'FINAL_INEXISTENT', timeout=timeout)
    return resp


def main():
    parser = argparse.ArgumentParser(description='Switch scanning tool.')
    parser.add_argument('--ip', dest='IP', help='the switch ip (eg. VLAN interface)', required=True)
    parser.add_argument('--password', dest='PASSWORD', help='Telnet password', required=True)
    parser.add_argument('--port', dest='PORT', default=23, help='Telnet port (default: 23)')
    parser.add_argument('--console', dest='CONSOLE_PASSWD', help='Console password if it\'s set')
    parser.add_argument('--timeout', dest='TIMEOUT', default=1, help='Timeout when interrogating the ISO (default: 1) (for an accurate response on old switches use a big timeout; eg. =5)')
    args = parser.parse_args()

    conn = telnet_connection(ip=args.IP, telnet_passwd=args.PASSWORD, console_passwd=args.CONSOLE_PASSWD, port=args.PORT)
    print(read_all(connection=conn, command='?').decode('ascii'))
    # print(read_all(connection=conn, command='show int sw\n', timeout=args.TIMEOUT).decode('ascii'))
    conn.close()


if __name__ == '__main__':
    main()