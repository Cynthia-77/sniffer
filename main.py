from winpcapy import WinPcapDevices
from winpcapy import WinPcapUtils

import dpkt
import time
import datetime, sys


def packet_callback(win_pcap, param, header, pkt_data):
    eth = dpkt.ethernet.Ethernet(pkt_data)

    parse_layer1(eth)


def parse_layer1(eth):  # 数据链路层
    # 分片
    # dmac = "-".join(["%02x" % (b) for b in pkt_data[0:6]])
    # smac = "-".join(["%02x" % (b) for b in pkt_data[6:12]])

    smac = "-".join(["%02x" % (b) for b in eth.src])
    dmac = "-".join(["%02x" % (b) for b in eth.dst])
    packet_type = type(eth)  # Ethernet

    # 输出数据包信息
    output1 = {'time': time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime()))}
    output2 = {'type': packet_type}
    output3 = {'smac': smac, 'dmac': dmac}
    print()
    print(output1)
    print(output2)
    print(output3)

    parse_layer2(eth.data)


def parse_layer2(packet):  # 网络层
    packet_type = type(packet)  # IP

    # 判断数据报类型
    if isinstance(packet, dpkt.ip.IP):  # IP数据报
        # 取出分片信息
        src = packet.src
        dst = packet.dst
        packet_len = packet.len  # 首部+数据
        id = packet.id
        df = bool(packet.off & dpkt.ip.IP_DF)  # don't fragment
        mf = bool(packet.off & dpkt.ip.IP_MF)  # more fragments (not last frag)
        offset = packet.off & dpkt.ip.IP_OFFMASK
        ttl = packet.ttl
        protocol = packet.p  # tcp udp
        checksum = packet.sum

        # 输出数据包信息
        output1 = {'type': packet_type}
        output2 = {'src': '%d.%d.%d.%d' % tuple(src), 'dst': '%d.%d.%d.%d' % tuple(dst)}
        output3 = {'id': id, 'len': packet_len}
        output4 = {'df': df, 'mf': mf, 'offset': offset}
        output5 = {'ttl': ttl}
        output6 = {'protocol': protocol}
        output7 = {'checksum': checksum}
        print(output1)
        print(output2)
        print(output3)
        print(output4)
        print(output5)
        print(output6)
        print(output7)
    else:
        print("Non IP packet type not supported ", packet.__class__.__name__)

    parse_layer3(packet.data)


def parse_layer3(packet):
    return


if __name__ == '__main__':
    # Return a list(dict) of all the devices detected on the machine
    devices_dict = WinPcapDevices.list_devices()
    # print(devices_dict)
    devices_list = []
    for keys, value in devices_dict.items():
        # 键和值都要
        temp = (keys, value)
        devices_list.append(temp)
    # print(devices_list)

    # Iterate over devices (in memory), with full details access
    k = -1
    with WinPcapDevices() as devices:
        for device in devices:
            k += 1
            print('序号 ' + str(k) + '   ')
            print(device.name, device.description, device.flags,
                  device.addresses.contents.netmask.contents.sa_family)

    print("------------------------------------------------")

    deviceIndex = int(input("请输入你想要监听的网卡序号: "))

    device_description = devices_list[deviceIndex][1]
    WinPcapUtils.capture_on(device_description, packet_callback)
