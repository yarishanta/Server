import socket
import os
import struct
import time

class STUNClient:

   # the following is a list of some public/free stun servers
   # some of them send the trasport address as both MAPPED-ADDRESS and XOR-MAPPED-ADDRESS -
   # and others send only MAPPED-ADDRESS
   stun_servers_list = (
   'stun.xten.com',       # 0
   'stun01.sipphone.com', # 1
   'stunserver.org',      # 2
   'stun.ideasip.com',    # 3 - no XOR-MAPPED-ADDRESS
   'stun.softjoys.com',   # 4 - no XOR-MAPPED-ADDRESS
   'stun.voipbuster.com', # 5 - no XOR-MAPPED-ADDRESS
   'stun.voxgratia.org',  # 6
   'numb.viagenie.ca',    # 7
   'stun.sipgate.net'     # 8 - ports 3478 & 10000
   )
   
   # for explanations about the following variables see the section 7.2.1 of RFC5389
   rc=7    # maximum number of the requests to send
   rm=16   # used for calculating the last receive timeout
   rto=0.5 # Retransmission TimeOut
   
   stun_server=None

   # whether debugging messages are printed or not
   print_debug_msgs=False

   def __init__(self, server=0, port=3478):
     if type(server)==int:
       self.stun_server=(self.stun_servers_list[server], port)
     else:
       self.stun_server=(server, port)   
   
   def show_binary_data(self, title, data):
     if not self.print_debug_msgs: return
     if title:
       print(title, end='')
     for b in data:
       print('\\x{0:02X}'.format(b), end='')
     print()

   def myprint(self, msg=''):
     if not self.print_debug_msgs: return
     print(msg)
	 
   def extract_ip(self, binary):
    ip=struct.unpack('BBBB', binary)
    ip=str(ip[0])+'.'+str(ip[1])+'.'+str(ip[2])+'.'+str(ip[3])
    return ip 

   def extract_port(self, binary):
     return struct.unpack('!H', binary)[0]
  
   def get_public_address_of_udp_socket(self, udp_socket): 

      self.myprint('STUN server: {0}:{1}'.format(self.stun_server[0], self.stun_server[1]))

      timeout_save=udp_socket.gettimeout()

      try:
      
        udp_socket.settimeout(0)
        try: udp_socket.recv(1280)
        except: pass

        maddr=b''  # mapped ip
        mport=b'' # mapped port

        xmaddr=b'' # xor mapped ip
        xmport=b'' # xor mapped port

        msg_type=b'\x00\x01' # STUN binding request
        body_length=b'\x00\x00' # we have/need no attributes, so message body length is zero
        magic_cookie=b'\x21\x12\xA4\x42'
        transaction_id=os.urandom(12)
        stun_request=msg_type+body_length+magic_cookie+transaction_id

        self.show_binary_data('\nSTUN request: ', stun_request)

        tout=self.rto/2 # since it is multiplied by 2 in the for loop, the first timeout will be equal to rto

        for r in range(0, self.rc):

          udp_socket.sendto(stun_request, self.stun_server)
        
          self.myprint("\n{0}th STUN request sent.".format(r+1))
        
          # the following timeout calculation algorithm is according to the section 7.2.1 of RFC5389
          if r < self.rc-1:
            tout*=2
          else:
            tout = self.rm*self.rto
        
          remaining_time=tout
        
          outer_countinue=False
        
          while remaining_time > 0:
            udp_socket.settimeout(remaining_time)
            try:
              self.myprint('waiting for response {0} sec(s)...'.format(remaining_time))
              time1=time.time()
              data=udp_socket.recv(1280) # this client has no IPv6 support yet, but enough data can be received here
            except Exception as e:
              if type(e)==socket.timeout:
                self.myprint("timeout exception occured in receiving STUN response: "+str(e))
                outer_countinue=True
                break
              elif type(e)==socket.error and hasattr(e, 'errno') and e.errno==10040:
                self.myprint('socket.error 10040 (data too big) occured.')
                continue
              else: raise
            finally:
              time2=time.time()
              remaining_time-=(time2-time1)
         
            self.show_binary_data('\nUDP data received:\n', data)

            if(len(data)<20):
              self.myprint('length too short. (not a STUN response)')
              # because we received an irrelevant udp packet that most probably caused the current recv to -
              # terminate prematurely, we continue the inner loop (waiting for receiving a STUN response)
              continue
        
            if data[4:20]!=magic_cookie+transaction_id:
              self.myprint('magic cookie and/or transaction id check failed!')
              # because we received an irrelevant udp packet that most probably caused the current recv to -
              # terminate prematurely, we continue the inner loop (waiting for receiving a STUN response)
              continue
         
            break # break the inner (waiting for receiving a STUN response) loop

          if outer_countinue: continue # recv timeout occured in the inner loop; so we countinue the main loop

		
          if data[0:2]!=b'\x01\x01':
            raise Exception('a non-success STUN response received.')
        
          response_body_length=struct.unpack('!h', data[2:4])[0]

          self.myprint()
        
          i=20 # current reading position in the response binary data
          while i < response_body_length+20: # proccessing the response
            self.show_binary_data('STUN attribute in response: ', data[i:i+2])
            if data[i:i+2]==b'\00\01': # MAPPED-ADDRESS
              maddr_start_pos=i+2+2+1+1
              mport=data[maddr_start_pos:maddr_start_pos+2]
              maddr=data[maddr_start_pos+2:maddr_start_pos+2+4]
            if data[i:i+2]==b'\x80\x20' or data[i:i+2]==b'\x00\x20':
              # apparently, all public stun servers tested use 0x8020 (in the Comprehension-optional range) -
              # as the XOR-MAPPED-ADDRESS Attribute type number instead of 0x0020 specified in RFC5389
              xmaddr_start_pos=i+2+2+1+1
              xmport=data[xmaddr_start_pos:xmaddr_start_pos+2]
              xmaddr=data[xmaddr_start_pos+2:xmaddr_start_pos+2+4]
            i+=2
            attrib_value_length=struct.unpack('!h', data[i:i+2])[0]
            if attrib_value_length%4:
              attrib_value_length+=4-(attrib_value_length%4) # adds stun attribute value padding
            i+=2
            i+=attrib_value_length

          break # quit the STUN request loop

        if maddr:
          self.show_binary_data('\nMAPPED-ADDRESS: ', maddr)
          self.show_binary_data('mport: ', mport)
        else:
          self.myprint('\nno MAPPED-ADDRESS found.')

        if xmaddr:
          n=struct.unpack('!I', xmaddr)[0]
          m=struct.unpack('!I', magic_cookie)[0]
          n=n^m
          self.show_binary_data('\nXOR-MAPPED-ADDRESS: ', struct.pack('!I', n))
          n2=struct.unpack('!H', xmport)[0]
          m2=struct.unpack('!H', magic_cookie[0:2])[0]
          n2=n2^m2
          self.show_binary_data('xmport: ', struct.pack('!H', n2))
        else:
          self.myprint('\nno XOR-MAPPED-ADDRESS found.')

        ip=None
        port=None
        if xmaddr: # we must prefer using XOR-MAPPED-ADDRESS over MAPPED-ADDRESS
          ip=self.extract_ip(struct.pack('!I', n))
          port=self.extract_port(struct.pack('!H', n2))
        elif maddr:
          ip=self.extract_ip(maddr)
          port=self.extract_port(mport)
        else:
          raise Exception('STUN query failed!')

      finally: udp_socket.settimeout(timeout_save)

      self.myprint('\n=======STUN========')
      self.myprint('IP: {0}'.format(ip))
      self.myprint('Port: {0}'.format(port))
      self.myprint('===================')

      return (ip, port)