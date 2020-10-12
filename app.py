#!/usr/bin/env python3.8

import pytest
import json
import paramiko
import regex as re


@pytest.fixture
def connect():
    with open('config.json') as f:
        args = json.load(f)

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

@pytest.mark.xfail
def test_native_vlan(connect):
    response = read_all(connection=connect, command='show vlan\n').decode('ascii')
    vlan_1 = re.search(r'([1]) +([a-zA-Z-/]+) +', response).groups() 
    assert vlan_1[1] != "default", "The native vlan should not be vlan 1. \
Move the user trafic to a different vlan. The native VLAN is used for a lot \
of management data such as DTP, VTP and CDP frames and also BPDU's for \
spanning tree. Try changing the native vlan to a different created vlan. Eg. \
command: Switch(config)#default vlan ANY-NUMBER-BUT-NOT-1"

def test_switchport_mac_address(connect):
    # port-security sa fie enable
    pass

def test_switchport_violation(connect):
    # port-security sa fie RESTRICT sau SHUTDOWN
    pass

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
