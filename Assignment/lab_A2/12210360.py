import argparse
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, ICMPv6EchoRequest, ICMPv6PacketTooBig
import socket
from scapy.layers.l2 import Ether


def pmtu(dest_addr: str, use_ipv6: bool = False, src_addr: str = None) -> int:
    """
    Discover the Path MTU (PMTU) to the specified destination address.
    Args:
    dest_addr (str): The destination IP address to probe.
    use_ipv6 (bool): Flag indicating whether to use IPv6 or IPv4.
    src_addr (str): The source IP address to use for sending packets.
    Returns:
    An integer value indicating the PMTU detection result.
    Raises:
    RuntimeError: If the address is invalid.
    """
    try:
        socket.inet_pton(socket.AF_INET, dest_addr) if not use_ipv6 else socket.inet_pton(socket.AF_INET6, dest_addr)
    except socket.error:
        raise RuntimeError(f"Invalid IP address: {dest_addr}")

    # ipv4
    if not use_ipv6:
        max_mtu = 1800
        min_mtu = 20
        mtu = (max_mtu + min_mtu) // 2
        header = 28

        # pkt
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        icmp_packet = ICMP()

        # print(packet)
        while True:
            if src_addr:
                packet = ether / IP(src=src_addr, dst=dest_addr, flags="DF") / icmp_packet / Raw("X" * mtu)
            else:
                packet = ether / IP(dst=dest_addr, flags="DF") / icmp_packet / Raw("X" * mtu)
            response = srp1(packet, timeout=2, verbose=False, iface=conf.iface)

            if not response:
                # print(f"No response for MTU={mtu}. Decreasing MTU.")
                max_mtu = mtu - 1
            else:
                if response.haslayer(ICMP):
                    icmp = response.getlayer(ICMP)
                    if icmp.type == 3 and icmp.code == 4:
                        # print(f"Fragmentation needed for MTU={mtu}. Decreasing MTU.")
                        max_mtu = mtu -1
                    else:
                        # print(f"type 0. Received normal response for MTU={mtu}. Increasing MTU.")
                        min_mtu = mtu
                else:
                    # print(f"Received non-ICMP response for MTU={mtu}. Increasing MTU.")
                    min_mtu = mtu

            mtu = (max_mtu + min_mtu) // 2

            if min_mtu >= max_mtu:
                # print("Finished probing the maximum MTU.")
                break
        return mtu + header
    else:
        max_mtu = 1499
        min_mtu = 1000
        mtu = (max_mtu + min_mtu) // 2
        header = 48

        # ether = Ether(dst="33:33:00:00:00:04")
        ether = Ether(dst="33:33")

        while min_mtu <= max_mtu:
            icmpv6_packet = ICMPv6EchoRequest(data=b"X" * (mtu-header))
            if src_addr:
                packet = ether / IPv6(src=src_addr, dst=dest_addr,hlim=64) / icmpv6_packet
                # packet = ether / IPv6 / ICMPv6EchoRequest() / ("X" * mtu)
            else:
                packet = ether / IPv6(dst=dest_addr,hlim=64) / icmpv6_packet

            # packet.show()
            # 发送数据包并接收响应
            response = srp1(packet, timeout=2, verbose=False, iface="Microsoft KM-TEST 环回适配器")
            if response:
                # response.show()
                if response.haslayer(ICMPv6PacketTooBig):
                    # print(f"MTU {mtu} 太大，收到 Packet Too Big 响应")
                    max_mtu = mtu -1
                else:
                    # print(f"MTU {mtu} 合适，收到正常响应")
                    min_mtu = mtu +1
            else:
                # print(f"未收到响应，MTU {mtu} 可能过大，调整范围")
                max_mtu = mtu - 1
            mtu = (max_mtu + min_mtu) // 2

            # 如果 min_mtu >= max_mtu，表示搜索结束
            if min_mtu >= max_mtu:
                # print(f"Finished probing the maximum MTU. Max MTU is {mtu}.")
                break
        return mtu


def main():
    parser = argparse.ArgumentParser(description='Discover the Path MTU along a network path.')
    parser.add_argument('destination', type=str, help='The destination IP address to probe.')
    parser.add_argument('--ipv6', action='store_true', help='Use IPv6 instead of IPv4.')
    parser.add_argument('--source', type=str, help='Optional source IP address to use for probing.')
    args = parser.parse_args()
    try:
        # Call the PMTU discovery function
        mtu = pmtu(dest_addr=args.destination, use_ipv6=args.ipv6,
                   src_addr=args.source)
        print(f"The Path MTU to {args.destination} is {mtu} bytes.")
    except RuntimeError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    main()
    # python 12210360.py 192.168.2.4 --source 192.168.0.1
    # python A2_3.py 192.168.0.101 --source 192.168.0.1
    # python 12210360.py fe02::4 --ipv6 --source fe00::1
    # python A2_3.py fe00::101 --ipv6 --source fe00::1
