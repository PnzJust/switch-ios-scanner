#!/usr/bin/env python3.8

import pytest
import json
import paramiko
import regex as re
import warnings
from termcolor import colored


@pytest.fixture(scope="session")
def args():
    with open('config.json') as f:
        args = json.load(f)
    if "IP" not in args:
        raise Exception("IP should be mentioned in config.json")
    elif not re.match(r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}",
                  args["IP"]):
        raise Exception("The IP is not valid.")

    if "PROTOCOL" not in args:
        raise Exception("PROTOCOL should be mentioned in config.json")
    elif args["PROTOCOL"] not in ["telnet", "ssh"]:
        raise Exception("Invalid protocol. Use telnet or ssh.")

    if "PASSWORD" not in args:
        raise Exception("PASSWORD should be mentioned in config.json")

    if "PORT" not in args:
        raise Exception("PORT should be mentioned in config.json")
    elif int(args["PORT"]) != args["PORT"] or \
         int(args["PORT"]) not in range(65536):
        raise Exception("Invalid port.")

    if "TIMEOUT" not in args:
        raise Exception("TIMEOUT should be mentioned in config.json")

    return args


@pytest.fixture(scope="function")
def connect(args):
    if args['PROTOCOL'] == "telnet":
        from telnetlib import Telnet
        conn = Telnet(args['IP'], args['PORT'])
        conn.read_until(b'Password: ')
        conn.write(str.encode(args['PASSWORD'] + '\n'))
        conn.write(b'enable\n')
        if args['CONSOLE_PASSWD']:
            conn.read_until(b'Password: ')
            conn.write(str.encode(args['CONSOLE_PASSWD'] + '\n'))
    elif args['PROTOCOL'] == "ssh":
        # SSH coming soon
        pass

    yield conn

    conn.close()


def read_all(connection, command, timeout=1):
    connection.write(str.encode(command))
    resp = connection.read_until(b'FINAL_INEXISTENT', timeout=timeout)
    while resp.endswith(b'--More-- '):
        connection.write(b' ')
        resp += connection.read_until(b'FINAL_INEXISTENT', timeout=timeout)
    return resp


def all_interfaces(conn):
    response = read_all(connection=conn, command='show interfaces status\n').decode('ascii')
    re_interfaces = re.findall(r"((Fa|Gi)([0-9]*/)*[0-9]*) +(notconnect|connected|disabled)", response)
    interfaces = [(interface[0], interface[3]) for interface in re_interfaces]
    return interfaces


def test_native_vlan(connect):
    response = read_all(connection=connect, command='show vlan\n').decode('ascii')
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
            response = read_all(connection=connect, command='show port-security interface ' + interface[0] + ' \n').decode('ascii')
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
            response = read_all(connection=connect, command='show port-security interface ' + interface[0] + ' \n').decode('ascii')
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
    pass

def test_acl(connect):
    # acl-ul sa nu aiba vreun 'deny all' in ale sale reguli
    pass

def test_ntp(connect):
    # de preferat sa fie disabled  (ntp peer)
    pass

def test_console_password(connect):
    # de preferat sa existe parola pe consola
    pass

def test_enable_password(connect):
    # de preferat sa existe parola pe enable
    pass

def test_vtp_password(connect):
    # de preferat sa aiba o parola (sh vtp pass)
    pass

def test_bpdu_guard(connect):
    # sa fie enablat pe toate porturile
    pass

def test_telnet(connect):
    # sa fie disabled, sa se limiteze accesul liniilor vty
    # sa se foloseasca servere RADIUS pentru AAA
    pass

def test_plaintext_passwords(connect):
    # sa nu fie salvata nici o parola in plaintext
    pass

def test_dtp(connect):
    # disabled dtp pentru a nu se forta un trunk intre switch si atacator
    pass

def test_dhcp(connect):
    # DHCP snooping
    pass

def test_vty_password(connect):
    # trebuie enablata
    pass

def test_snmp(connect):
    # disable (info disclosure)
    pass

def test_source_routing(connect):
    # disable (no ip source-route)
    pass

def test_subnet_broadcast(connect):
    # disable (no ip directed-broadcast)
    pass

def test_tcp_small_servers(connect):
    # disable (no service tcp-small-servers)
    pass

def test_udp_small_servers(connect):
    # disable (no service udp-small-servers)
    pass

def test_service_finger(connect):
    # disable (no service finger)
    pass

def test_log_review(connect):
    # snmp log target
    pass

def test_dynamic_routing_keys(connect):
    # protocol authenitcation-key
    pass

def test_icmp_redirects(connect):
    # deny icmp any any
    pass

def test_proxy_arp(connect):
    # no ip proxy-arp
    pass

def test_llc(connect):
    # disable (set spantree root)
    pass

def test_802_1q(connect):
    pass

def test_stp(connect):
    pass

def test_vqp(connect):
    pass

def test_root_guard(connect):
    pass

def test_etherchannel_guard(connect):
    pass

def test_loop_guard(connect):
    pass

def test_mtu_master_interface(connect):
    pass

def test_bandwith(connect):
    pass

def test_sfp(connect):
    pass

def test_virtual_link_aggregation_group(connect):
    pass

def test_igmp_snooping(connect):
    pass

def test_lacp(connect):
    pass

def test_dhcp_relay(connect):
    pass

def test_lldp(connect):
    pass

def test_fdb(connect):
    pass

def test_pagp(connect):
    pass

def test_mpls(connect):
    pass

def test_aaa(connect):
    pass

def test_alias(connect):
    pass

def test_boot(connect):
    pass

def test_buffers(connect):
    pass

def test_cns(connect):
    pass

def test_errdisable(connect):
    pass

def test_exception(connect):
    pass

def test_hostname(connect):
    pass

def test_priority_list(connect):
    pass

def test_privilege(connect):
    pass

def test_queue_list(connect):
    pass

def test_rmon(connect):
    pass

def test_rtr(connect):
    pass

def test_system_mtu(connect):
    pass

def test_udld(connect):
    pass

def test_vmps(connect):
    pass

def test_wrr_queue(connect):
    pass

def test_duplex(connect):
    pass

def test_hold_queue(connect):
    pass

def test_keepalive(connect):
    pass

def test_timeout(connect):
    pass
