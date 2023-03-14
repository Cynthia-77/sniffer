import time

import dpkt
from winpcapy import WinPcapUtils
from winpcapy import WinPcapDevices


def packet_callback(win_pcap, param, header, pkt_data):
    eth = dpkt.ethernet.Ethernet(pkt_data)

    # smac = eth.src
    # dmac = eth.dst
    type = eth.type
    # print(smac, dmac, type)

    dmac = "-".join(["%02x" % (b) for b in pkt_data[0:6]])
    smac = "-".join(["%02x" % (b) for b in pkt_data[6:12]])

    # # 判断是否为IP数据报
    if not isinstance(eth.data, dpkt.ip.IP):
        print("Non IP packet type not supported ", eth.data.__class__.__name__)
        return
    # 抓IP数据包
    packet = eth.data
    # 取出分片信息
    df = bool(packet.off & dpkt.ip.IP_DF)
    mf = bool(packet.off & dpkt.ip.IP_MF)
    offset = packet.off & dpkt.ip.IP_OFFMASK

    # 输出数据包信息：time,smac,dmac,src,dst,protocol,length,ttl,df,mf,offset,checksum
    output1 = {'time': time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime()))}
    output0 = {'smac': smac, 'dmac': dmac}
    output2 = {'src': '%d.%d.%d.%d' % tuple(packet.src), 'dst': '%d.%d.%d.%d' % tuple(packet.dst)}
    output3 = {'protocol': packet.p, 'len': packet.len, 'ttl': packet.ttl}
    output4 = {'df': df, 'mf': mf, 'offset': offset, 'checksum': packet.sum}
    print()
    print(output1)
    print(output0)
    print(output2)
    print(output3)
    print(output4)


if __name__ == '__main__':
    # Return a list of all the devices detected on the machine
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
