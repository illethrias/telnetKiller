#!/usr/bin/env python

import configparser
import logging
import argparse
import socket
import os
import ipaddress
import sys
from telnetlib import Telnet

logger = logging.getLogger('telnet_killer')
logger.setLevel(logging.WARNING)


def scan_ip(ip, ports=[23]):
    results = {}
    for port in ports:
        results[port] = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print("IP {}:   Port {}: 	 Open".format(ip, port))
                results[port] = True
            sock.close()
        except socket.error:
            print("Couldn't connect to server")
    return results


def stop_telnet(ip, username=None, password=None):
    if username is None and password is None:
        tn = Telnet(ip)
        cmd = "killall telnetd\r\n"
        tn.write(cmd.encode())
        print(tn.read_until(b'!', timeout=10).decode())


# todo: add possibility for specify blacklist/whitelist
# todo: add possibility for add credentials for the devices
# todo: change from print to log
def load_configfile(c_parser, path):
    try:
        c_parser.read(path)
    except configparser.MissingSectionHeaderError:
        # todo: add link to repo for README
        print('Warning: config file: ' + path + 'contains no section headers, consult README')


def print_config(conf):
    for s in conf.sections():
        print(s)
        for i in conf[s]:
            print(i, conf.get(s, i))


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Killing unsecured telnet in your network')
    parser.add_argument('--scan', action="store_true",
                        help='scan the network')
    parser.add_argument('--subnet', help='specify subnet for the scan')
    parser.add_argument('--config', action='store', default='./',
                        help="location of the config file/files, by default it will load all *.ini in current directory.")
    parser.add_argument('--auto-kill',
                        help="if scan is activated it won't kill telnet, to automatically kill all found unsecured telnet use this flag. ")
    args = parser.parse_args()
    config = configparser.ConfigParser()
    # load config
    # test if config is file or directory
    if os.path.isfile(args.config):
        load_configfile(config, args.config)
    elif os.path.isdir(args.config):
        for f in sorted(os.listdir(args.config)):
            if f.endswith('.ini'):
                load_configfile(config, os.path.join(args.config, f))
    else:
        print("Error specified path to config file/files, is not a file nor directory!")
        sys.exit(1)

    # check if config has all required fields according to flags

    if args.scan:
        if args.subnet is not None:
            try:
                subnet = ipaddress.ip_interface(args.subnet).network
                for host in subnet.hosts():
                    scan_ip(str(host))
            except ValueError as ve:
                print('specified subnet does not apear to be valid, please use format: net_addr/net_mask')
                sys.exit(1)
        elif 'scan' in config.sections():
            pass

    print_config(config)
    for section in config:
        if section == 'scan':
            if 'subnet' in config['scan']:
                subnet = ipaddress.ip_network(config['scan']['subnet'])
                for host in list(subnet.hosts()):
                    if scan_ip(str(host), [23]):
                        print("Telnet found on host: " + str(host))
        elif section == 'DEFAULT':
            pass
        else:
            if config[section]['whitelist'] == 'True':
                pass
            else:
                try:
                    stop_telnet(section)
                except ConnectionRefusedError as CRe:
                    print('connection was refused, verify if telnet is running on: '+section)


