import stun_client
import socket

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sc=stun_client.STUNClient()
sc.print_debug_msgs=True

try:
  print(sc.get_public_address_of_udp_socket(udp_socket))
except Exception as e:
  print('\nAn exception occured in get_public_address_of_udp_socket:\n', e)

input("\nhit Enter to quit...")