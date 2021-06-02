#!/usr/bin/env python3.8

import json
import warnings
import pytest
import regex as re
from termcolor import colored


@pytest.fixture(scope="session")
def args():
    with open('config.json') as file:
        file_args = json.load(file)
    if "IP" not in file_args:
        raise Exception("IP should be mentioned in config.json")
    elif not re.match(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}",
                  file_args["IP"]):
        raise Exception("The IP is not valid.")

    if "PROTOCOL" not in file_args:
        raise Exception("PROTOCOL should be mentioned in config.json")
    elif file_args["PROTOCOL"] not in ["telnet", "ssh"]:
        raise Exception("Invalid protocol. Use telnet or ssh.")

    if file_args["PROTOCOL"] == "ssh":
        if "USERNAME" not in file_args:
            raise Exception("USERNAME should be mentioned in config.json")
        if "SSH_PASSWORD" not in file_args:
            raise Exception("SSH_PASSWORD should be mentioned in config.json")

    if "SWITCH_PASSWORD" not in file_args:
        raise Exception("SWITCH_PASSWORD should be mentioned in config.json")

    if "PORT" not in file_args:
        raise Exception("PORT should be mentioned in config.json")
    elif int(file_args["PORT"]) != file_args["PORT"] or \
         int(file_args["PORT"]) not in range(65536):
        raise Exception("Invalid port.")

    return file_args


@pytest.fixture(scope="function")
def connect(args):
    if args['PROTOCOL'] == "telnet":
        from telnetlib import Telnet
        conn = Telnet(args['IP'], args['PORT'])
        conn.read_until(b'Password: ')
        conn.write(str.encode(args['SWITCH_PASSWORD'] + '\n'))
        conn.write(b'enable\n')
        if args['ENABLE_PASSWD']:
            conn.read_until(b'Password: ')
            conn.write(str.encode(args['ENABLE_PASSWD'] + '\n'))
    elif args['PROTOCOL'] == "ssh":
        import paramiko
        conn = paramiko.Transport((args['IP'], args['PORT']))
        conn.connect(username=args['USERNAME'], password=args['SSH_PASSWORD'])
        conn = conn.open_channel(kind='session')
    
    # Check if the connection is established
    response = read_all(connection=conn, command='show version\n')
    if len(response.split("\n")) < 4:
        raise Exception(colored("The connection could not be established using \
your credentials. Check them again: " + str(args) , "red"))

    yield conn
    conn.close()


def read_all(connection, command, timeout=1):
    if hasattr(connection, 'write'): # if is telnet
        connection.write(str.encode(command))
        resp = connection.read_until(b'FINAL_INEXISTENT', timeout=timeout)
        while resp.endswith(b'--More-- '):
            connection.write(b' ')
            resp += connection.read_until(b'FINAL_INEXISTENT', timeout=timeout)
    elif hasattr(connection, 'exec_command'): # it is ssh
        connection.exec_command(command)
        resp = connection.recv(4096)
        while resp.endswith(b'--More-- '):
            connection.exec_command(b' ')
            resp += connection.recv(4096)

    return resp.decode('ascii')


def all_interfaces(conn):
    response = read_all(connection=conn, command='show interfaces status\n')
    re_interfaces = re.findall(r"((Fa|Gi)([0-9]*/)*[0-9]*) +(notconnect|connected|disabled)",
                               response)
    interfaces = [(interface[0], interface[3]) for interface in re_interfaces]
    return interfaces


def all_vlans(conn):
    response = read_all(connection=conn, command='show vlan brief\n')
    re_vlans = re.findall(r"([0-9]+) +([a-zA-Z0-9]*) +active(.*)", response)
    vlans = [(vlan[0], vlan[1]) for vlan in re_vlans]
    return vlans


def test_native_vlan(connect):
    response = read_all(connection=connect, command='show vlan\n')
    vlan_1 = re.search(r'([1]) +([a-zA-Z-/]+) +', response).groups()
    if vlan_1[1] == "default":
        warnings.warn(colored("The native vlan should not be vlan 1. \
Move the user trafic to a different vlan. The native VLAN is used for a lot \
of management data such as DTP, VTP and CDP frames and also BPDU's for \
spanning tree. Try changing the native vlan to a different created vlan. Eg. \
command: Switch(config)#default vlan ANY-NUMBER-BUT-NOT-1", "yellow"), Warning)


def test_switchport_port_security(connect):
    interfaces = all_interfaces(conn=connect)
    no_port_security_interfaces = ""
    for interface in interfaces:
        if interface[1] == "connected":
            response = read_all(connection=connect,
                                command='show port-security interface ' + interface[0] + ' \n')
            status = re.search(r"Port Security +: (.*)", response).groups()
            if "Enabled\r" not in status[0]:
                no_port_security_interfaces += interface[0] + " "
    if no_port_security_interfaces:
        raise Exception(colored("Port Security is not enabled for interfaces: {}.\
This missconfiguration could lead to different vulnerabilites like:\
MITM, CAM overflow. You should enable the port-security on \
all access ports. Eg. command: Switch(config-if)#switchport \
port-security".format(no_port_security_interfaces), "red"))


def test_switchport_port_security_violation(connect):
    interfaces = all_interfaces(conn=connect)
    no_port_security_violation_interfaces = ""
    for interface in interfaces:
        if interface[1] == "connected":
            response = read_all(connection=connect,
                                command='show port-security interface ' + interface[0] + ' \n')
            status = re.search(r"Violation Mode +: (.*)", response).groups()
            if "Restrict\r" not in status[0] and "Shutdown\r" not in status[0]:
                no_port_security_violation_interfaces += interface[0] + " "
    if no_port_security_violation_interfaces:
        raise Exception(colored("Port Security Violation Mode is not enabled for interfaces: {}.\
This missconfiguration could lead to different vulnerabilites like:\
MITM, CAM overflow. You should enable the port-security on \
all access ports. Eg. command: Switch(config-if)#switchport \
port-security".format(no_port_security_violation_interfaces), "red"))


def test_cdp(connect):
    # sa fie disabled (cmd: no cdp run) pt ca mesajele cdp sunt
    # neencriptate/neautentificate
    interfaces = all_interfaces(conn=connect)
    cdp_interfaces = ""
    for interface in interfaces:
        if interface[1] == "connected":
            response = read_all(connection=connect,
                                command='show cdp interface ' + interface[0] + ' \n')
            status = re.search(r"(.*) (is) (.*),(.*)", response)
            if status is  None:
                continue
            status = status.groups()
            if status[2] == "up":
                cdp_interfaces += interface[0] + " "
    if cdp_interfaces:
        raise Exception(colored("CDP is enabled for interfaces: {}.\
This missconfiguration could lead to information disclosure because \
messages are sent unencrypted and unauthenticated. You should disable the cdp on \
all ports. Eg. command: Switch(config)#no cdp run".format(cdp_interfaces), "red"))


def test_acl(connect):
    # acl-ul sa nu aiba vreun 'deny all' in ale sale reguli
    response = read_all(connection=connect, command='show access-lists\n')
    if "deny   any" in response:
        warnings.warn(colored("There is a 'deny all' statement in your access \
list. This statement is by default at the end of all access lists. You \
could delete this statement and review your access lists.", "yellow"), Warning)


def test_console_password(connect):
    # de preferat sa existe parola pe consola
    response = read_all(connection=connect,
                        command='show running-config | begin line con 0\n',
                        timeout=5).split('\n')
    line_console_0_response = [response[2][:-1]]
    for e in response[3:]:
        if e[0] != ' ':
            break
        line_console_0_response.append(e[1:-1])
    login = False
    password = False
    password_encrypted = False
    for e in line_console_0_response:
        if 'login' in e:
            login = True
        elif 'password' in e:
            password = True
            if len(e.split(" ")) > 2:
                password_encrypted = True

    if not login:
        warnings.warn(colored("You forgot to enable your login on your \
console connection. Without this everybody will be able to connect \
without a password. Enable command: Switch(config-line)#login", "yellow"), Warning)
    if not password:
        warnings.warn(colored("You forgot to set a pass on your \
console connection. Without this password everybody will be able to connect \
to your switch.", "yellow"), Warning)
    elif not password_encrypted:
        warnings.warn(colored("You forgot to encrypt your password for \
console connection. Without this the password is stored unencrypted in your \
config file.", "yellow"), Warning)


def test_enable_password(connect):
    # de preferat sa existe parola pe enable
    response = read_all(connection=connect,
                        command='show running-config | include enable password\n',
                        timeout=5)
    password = response.split('\n')
    if len(password) < 4:
        warnings.warn(colored("You forgot to use a password for switch configuration. \
Without this everybody can config the switch without a password.", "yellow"), Warning)
    else:
        password = password[2].split(" ")
        if len(password) < 4:
            warnings.warn(colored("You forgot to encrypt your password for \
switch configuration. Without this the password is stored unencrypted in your \
config file.", "yellow"), Warning)


def test_vtp_password(connect):
    # de preferat sa aiba o parola (sh vtp status)
    response = read_all(connection=connect, command='show vtp status\n', timeout=2)
    status = re.search(r"VTP Operating Mode +: (.*)", response).groups()
    status = status[0][:-1]
    if status != 'Transparent':
        response = read_all(connection=connect, command='show vtp password\n')
        if ':' not in response:
            raise Exception(colored("VTP is runnig without a password. \
This missconfiguration could lead to a DoS through VTP spoofing. \
If you want to use this protocol you should use it with a strong password. \
Eg. command: Switch(config)#vtp password ^FV'(Oq2_ .", "red"))


def test_telnet(connect):
    # sa fie disabled, sa se limiteze accesul liniilor vty
    # sa se foloseasca servere RADIUS pentru AAA
    response = read_all(connection=connect,
                        command='show running-config | include telnet\n',
                        timeout=5).split('\n')
    if len(response) > 3:
        warnings.warn(colored("Telnet is enabled. You should use \
ssh otherwise your trafic will be unencrypted.", "yellow"), Warning)


def test_dtp(connect):
    # disabled dtp pentru a nu se forta un trunk intre switch si atacator
    response = read_all(connection=connect, command='show dtp\n').split('\n')
    response = response[-2][1:-1]
    if not response.startswith('0'):
        raise Exception(colored("DTP is runnig on {} port(s). You \
should disable DTP on all runnig ports so any attacker \
could not force a trunk between him and switch.".format(response.split(" ")[0]), "red"))


def test_dhcp(connect):
    # DHCP snooping
    response = read_all(connection=connect,
                        command='show running-config | include ip dhcp snooping\n',
                        timeout=5)
    if len(response.split('\n')) < 4:
        raise Exception(colored("DHCP is not runnig in snooping mode. This \
could lead to vulnerabilites like DHCP starving or DHCP rogue.", "red"))


def test_tcp_small_servers(connect):
    # disable (no service tcp-small-servers)
    response = read_all(connection=connect,
                        command='show running-config | include service tcp-small-servers\n',
                        timeout=5)
    if len(response.split('\n')) > 3:
        warnings.warn(colored("Tcp-small-servers service is runnig.", "yellow"), Warning)


def test_udp_small_servers(connect):
    # disable (no service udp-small-servers)
    response = read_all(connection=connect,
                        command='show running-config | include service udp-small-servers\n',
                        timeout=5)
    if len(response.split('\n')) > 3:
        warnings.warn(colored("Udp-small-servers service is runnig.", "yellow"), Warning)


def test_service_finger(connect):
    # disable (no service finger)
    response = read_all(connection=connect,
                        command='show running-config | include finger\n',
                        timeout=5)
    if len(response.split('\n')) > 3:
        warnings.warn(colored("Finger service is runnig.", "yellow"), Warning)


def test_all_ports_are_healthy(connect):
    response = read_all(connection=connect, command='show ip interface brief\n')
    response = re.findall(r"((FastEthernet|GigabitEthernet|Vlan)([0-9]*/*)*) +(.*) +(.*)", response)
    for e in response:
        if "YES" not in e[3]:
            warnings.warn(colored("{} is not ok.".format(e[0]), "yellow"), Warning)


def test_802_1x(connect):
    # sysauthcontrol should be Enabled
    response = read_all(connection=connect, command='show dot1x | include Sysauthcontrol\n')
    if "Disabled" in response:
        raise Exception(colored("802.1X authentication mechanism is not enabled. \
Now devices could attach to LANs and WLANs.", "red"))


def test_stp_bpduguard(connect):
    response = read_all(connection=connect,
                        command='show spanning-tree summary totals | include BPDU Guard\n')
    if "disabled" in response:
        raise Exception(colored("BPDU guard is disabled. This could lead to STP attacks.", "red"))


def test_stp_root_guard(connect):
    response = read_all(connection=connect,
                        command='show running-config | include spanning-tree guard root\n',
                        timeout=5)
    if len(response.split('\n')) < 4:
        warnings.warn(colored("STP guard root is not enabled on your switch.", "yellow"), Warning)


def test_stp_loopguard(connect):
    response = read_all(connection=connect,
                        command='show spanning-tree summary totals | include Loopguard Default\n')
    if "disabled" in response:
        raise Exception(colored("LOOP guard is disabled. This could lead to STP attacks.", "red"))


def test_igmp_snooping(connect):
    vlans = all_vlans(conn=connect)
    for vlan in vlans:
        response = read_all(connection=connect,
                            command='show ip  igmp snooping \
vlan {} | begin Vlan {}\n'.format(vlan[0], vlan[0]))
        if "Disabled" in response.split("\n")[3]:
            raise Exception(colored("IGMP snooping is not enabled for VLAN \
{}. This could lead to DoS attacks.".format(vlan[0]), "red"))


def test_aaa(connect):
    response = read_all(connection=connect,
                        command='show running-config | include aaa\n',
                        timeout=5)
    if len(response.split("\n")) < 4:
        warnings.warn(colored("AAA protocol is not enabled on your switch.", "yellow"), Warning)


def test_errdisable(connect):
    response = read_all(connection=connect, command='show errdisable detect\n')
    response = re.findall(r"([a-zA-Z0-9]*) +(Enabled|Disabled).*", response)
    for e in response:
        if e[1] == 'Disabled':
            warnings.warn(colored("{} has errdisable detection disabled".format(e[0]), "yellow"),
                          Warning)


def test_vmps(connect):
    response = read_all(connection=connect,
                        command='show running-config | include vmps server\n',
                        timeout=5)
    response = response.split("\n")
    if len(response) < 4:
        warnings.warn(colored("VMPS is not enabled.", "yellow"), Warning)
    else:
        response = response[2].split(" ")
        response = response[2]
        print("Switch has VMPS enabled to ip: ", response)


def test_tacacs_server(connect):
    response = read_all(connection=connect,
                        command='show running-config | include tacacs-server\n',
                        timeout=5)
    response = response.split("\n")
    host = False
    key = False
    for e in response:
        if "host" in e:
            host = True
            print("Tacacs Server is: ", e.split(" ")[-1])
        elif "key" in e:
            key = True
    if not host:
        warnings.warn(colored("Switch is running without a tacacs server", "yellow"), Warning)
    elif not key:
        warnings.warn(colored("Switch is connecting to a tacacs server without \
any authentication key.", "yellow"))


def test_return_ips(connect):
    response = read_all(connection=connect,
                        command='show ip interface brief | exclude unassigned\n')
    response = re.findall(r"((FastEthernet|GigabitEthernet|Vlan)([0-9]*/*)*) +(.*) +(.*)", response)
    if response:
        print("\nInterfaces IPs:")
        for e in response:
            print ("{}: {}".format(e[0], e[3].split(" ")[0]))
    else:
        print("\n")


def test_return_active_vlans(connect):
    response = read_all(connection=connect, command='show vlan brief\n')
    response = re.findall(r"([0-9]+) +([a-zA-Z0-9]*) +active(.*)", response)
    if response:
        print("\nActive Vlans and their names:")
        for e in response:
            print("VLAN{} <-> {}".format(e[0], e[1]))
    else:
        print("\n")


def test_banner_login(connect):
    response = read_all(connection=connect,
                        command='show running-config | include banner login\n',
                        timeout=5)
    response = response.split("\n")
    if len(response) > 3:
        response = response[2].split(" ")[2][2:-3]
        print("\nBanner login: ", response)
    else:
        print("\n")


def test_banner_motd(connect):
    response = read_all(connection=connect,
                        command='show running-config | include banner motd\n',
                        timeout=5)
    response = response.split("\n")
    if len(response) > 3:
        response = response[2].split(" ")[2][2:-3]
        print("\nBanner motd: ", response)
    else:
        print("\n")


def test_hostname(connect):
    response = read_all(connection=connect,
                        command='show running-config | include hostname\n',
                        timeout=5)
    response = response.split("\n")
    if len(response) > 3:
        response = response[2]
        response = response.split(" ")[1]
        response = response[:-1]
        print("\nSwitch hostname: ", response)
    else:
        print("\n")


def test_privilege(connect):
    response = read_all(connection=connect, command='show privilege\n')
    response = response.split('\n')
    response = response[1][:-1]
    print(response)


def test_default_gateway(connect):
    response = read_all(connection=connect,
                        command='show running-config | include ip default-gateway\n',
                        timeout=5)
    response = response.split("\n")
    if len(response) < 4:
        print("Switch is not accessible from the internet")
    else:
        response = response[2].split(" ")
        warnings.warn(colored("Switch is accessible from the internet through the \
ip: " + str(response[2]), "yellow"), Warning)
