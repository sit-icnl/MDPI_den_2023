import random
import string
import ipaddress
from scapy.all import *


def generate_random_payload(min_len, max_len):
    """
    Generate random text with random length.
    
    :param min_len: minimum text length
    :param max_len: maximum text length
    :return:        string
    """
    
    # generate random text length
    random_int = random.randint(min_len, max_len)
    
    # generate random string
    letters = string.ascii_letters
    random_payload = ''.join(random.choice(letters) for i in range(random_int))
    # print(f'The length of the random generated payload is: {len(random_payload)}')
    
    return random_payload


def generate_random_ipv4():
    """
    Generate random IP address.
    
    :return: IP address
    """
 
    random_ip_address = RandIP()
    
    # check if the generated ip address is reserved
    # if yes, re-generate
    while ipaddress.ip_address(random_ip_address).is_reserved:
        random_ip_address = RandIP()
    
    return  random_ip_address


def generate_random_ip_from_source(source):
    """
    Random select an IP address from the source.
    
    :param source: a list of IP address
    :return:       string, an ip address, e.g. '10.0.0.8'
    """
    
    return random.choice(source)


def generate_random_protocol(protocol_list, weights):
    """
    Random select a protocol based on the weights.
    
    :param protocol_list: a list of protocols
    :param weights:       a list of the weights corresponding to each protocol
    :return:              a protocol
    """
    
    return random.choices(protocol_list, weights)[0]