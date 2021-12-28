"""
Algo :

1. Create an ARP request directed to broadcast MAC asking for IP
2. Send packet and receive response
3. Parse the request
4. Print result

"""

# !/usr/bin/env python3

import scapy.all as scapy
import optparse

# def scan(ip):
#     scapy.arping(ip)


def get_argument():
    parse = optparse.OptionParser()
    # print(parse)
    parse.add_option("-t", "--target", dest="target", help="Enter your IP range that you want to scan")
    (options, arguments) = parse.parse_args()
    if not options.target:
        parse.error("[-] Please enter interface and new mac address value or type --help for more information")
    return options



def my_scan(ip):
    # Step1. Create an ARP request directed to broadcast MAC asking for IP
    # generate an ARP packet
    arp_request = scapy.ARP(pdst=ip)
    # print(arp_request.summary())
    # check the parameter of scapy.ARP()
    # scapy.ls(scapy.ARP())
    # then we need to send a broadcast for all available devices in our network.
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # print(broadcast.summary()) check the parameter in scapy.Ether() class | dst = "ff:ff:ff:ff:ff:ff" already set.
    # but if it is not set, we need to set the value is scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # scapy.ls(scapy.Ether())
    broadcast_arp_request = broadcast / arp_request
    # check details of broadcast_arp_request packet
    # broadcast_arp_request.show()
    # Step2. Send packet and receive response
    answered_list, unanswered_list = scapy.srp(broadcast_arp_request, timeout=1)
    # print(answered_list.summary())
    client_list = []
    # print("IP\t\t\tMAC Address")
    # print("=============================================================================")
    for element in answered_list:
        # print(element[1].show())
        # print(element[1].psrc)
        # print(element[1].hwsrc)
        # print(f"{element[1].psrc}\t\t{element[1].hwsrc}")
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def show_result(client_list):
    print("IP\t\t\tMAC Address")
    print("==============================================================================")
    for ele in client_list:
        print(f"{ele['ip']}\t\t{ele['mac']}")
    print("==============================================================================")


option = get_argument()
print(option)
connected_device_list = my_scan(option.target)
show_result(connected_device_list)