from winpcapy import WinPcapDevices, WinPcap
from winpcapy import WinPcapUtils
from scapy.all import *
import dpkt
import time
import datetime, sys

frame_index = 0


def packet_callback(win_pcap, param, header, pkt_data):
    global frame_index
    frame_index += 1

    output1 = {'Frame': frame_index}
    output2 = {'time': time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime()))}
    print()
    print(output1)
    print(output2)

    parse(pkt_data)


def parse(pkt_data):
    print(pkt_data)
    print([pkt_data])
    print(type(pkt_data))
    eth = dpkt.ethernet.Ethernet(pkt_data)

    parse_layer1(eth)


def parse_layer1(eth):  # 数据链路层
    # 分片
    # dmac = "-".join(["%02x" % (b) for b in pkt_data[0:6]])
    # smac = "-".join(["%02x" % (b) for b in pkt_data[6:12]])

    smac = "-".join(["%02x" % (b) for b in eth.src])
    dmac = "-".join(["%02x" % (b) for b in eth.dst])
    packet_type = type(eth)  # Ethernet
    data_protocol = eth.type

    # 输出数据包信息
    output1 = packet_type
    output2 = {'smac': smac, 'dmac': dmac}
    output3 = {'type': data_protocol}
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
        version = packet.v
        head_len = packet.hl
        type_of_service = packet.tos
        packet_len = packet.len  # 首部+数据
        id = packet.id
        # df = bool(packet.off & dpkt.ip.IP_DF)  # don't fragment
        # mf = bool(packet.off & dpkt.ip.IP_MF)  # more fragments (not last frag)
        # offset = packet.off & dpkt.ip.IP_OFFMASK
        df = packet.df  # don't fragment
        mf = packet.mf  # more fragments (not last frag)
        offset = packet.offset
        ttl = packet.ttl
        protocol = packet.p  # tcp udp
        checksum = packet.sum

        # 输出数据包信息
        output1 = {'type': packet_type, 'version': version}
        output2 = {'src': '%d.%d.%d.%d' % tuple(src), 'dst': '%d.%d.%d.%d' % tuple(dst)}
        output8 = {'head len': head_len}
        output9 = {'Type of service': type_of_service}
        output3 = {'id': id, 'len': packet_len}
        output4 = {'df': df, 'mf': mf, 'offset': offset}
        output5 = {'ttl': ttl}
        output6 = {'protocol': protocol}
        output7 = {'checksum': checksum}
        print(output1)
        print(output2)
        print(output8)
        print(output9)
        print(output3)
        print(output4)
        print(output5)
        print(output6)
        print(output7)
    else:
        print("Non IP packet type not supported ", packet.__class__.__name__)

    parse_layer3(packet.data)


def parse_layer3(packet):  # 传输层
    packet_type = type(packet)  # TCP

    # 判断数据报类型
    if isinstance(packet, dpkt.tcp.TCP):  # 解包，判断传输层协议是否是TCP，即当你只需要TCP时，可用来过滤
        sport = packet.sport
        dport = packet.dport
        seq = packet.seq
        ack = packet.ack
        offset = packet.off
        flags = packet.flags
        window_size = packet.win
        urp = packet.urp
        opts = packet.opts
        opts = dpkt.tcp.parse_opts(opts)

        # 输出数据包信息
        output1 = {'type': packet_type}
        output2 = {'sport': sport, 'dport': dport}
        output3 = {'seq': seq, 'ack': ack}
        output7 = {'offset': offset}
        output4 = {'flags': flags, 'window': window_size}
        output5 = {'urgent pointer': urp}
        output6 = {'options': opts}
        print(output1)
        print(output2)
        print(output3)
        print(output7)
        print(output4)
        print(output5)
        print(output6)
    elif isinstance(packet, dpkt.udp.UDP):  # UDP
        sport = packet.sport
        dport = packet.dport
        ulen = packet.ulen
        checksum = packet.sum

        # 输出数据包信息
        output1 = {'type': packet_type}
        output2 = {'sport': sport, 'dport': dport}
        output3 = {'length': ulen}
        output4 = {'checksum': checksum}
        print(output1)
        print(output2)
        print(output3)
        print(output4)
    else:
        print("Non TCP/UDP packet type not supported ", packet.__class__.__name__)

    parse_layer4(packet.data)


def parse_layer4(packet):  # 应用层
    if not len(packet):  # 如果应用层负载长度为0，即该包为单纯的tcp包，没有负载，则丢弃
        return

    packet_type = type(packet)  # HTTPS
    print(packet_type)

    if isinstance(packet, dpkt.http.Message):  # HTTP
        pass


if __name__ == '__main__':
    # Return a list(dict) of all the devices detected on the machine
    devices_dict = WinPcapDevices.list_devices()
    # print(devices_dict)
    devices_name_list = []
    for name, description in devices_dict.items():
        tmp = (name, description)
        devices_name_list.append(tmp)
    print(devices_name_list)

    # devices = []
    # print(conf.route)
    # for i in repr(conf.route).split('\n')[1:]:
    #     tmp = re.search(r'[a-zA-Z](.*)[a-zA-Z0-9]', i).group()[0:44].rstrip()
    #     if len(tmp) > 0:
    #         devices.append(tmp)
    # devices = list(set(devices))
    # devices.sort()
    # print(devices)
    #
    # sniff(iface=devices[0], prn=packet_callback)

    with WinPcap(devices_name_list[2][0]) as capture:
        capture.run(packet_callback)  # 只抓一个包

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

    device_description = devices_name_list[deviceIndex]
    print(device_description)
    # WinPcapUtils.capture_on(device_description, packet_callback)
    # device_name = devices_list[deviceIndex][0]
    # print(device_name)
    WinPcapUtils.capture_on_device_name(device_description, packet_callback)
    device_name, desc = WinPcapDevices.get_matching_device(device_description)
    print(device_name)
    if device_name is not None:
        with WinPcap(device_name) as capture:
            capture.run(callback=packet_callback)
            time.sleep(3)
            # device_name, desc = WinPcapDevices.get_matching_device(device_description)
            capture.stop()
