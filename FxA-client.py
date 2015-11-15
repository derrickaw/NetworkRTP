import random
import socket
import struct
from threading import Timer
import sys
import binascii


seq_num = 5
ack_num = 3
window_size = 1
buff_size = 1024

# TODO: Pack Header '!LLHLBLH'

# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s += w

    s = (s >> 16) + (s & 0xffff)
    s += s >> 16

    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

def send(ack, syn, fin, nack, ip_address, port):
    flags = pack_bits(ack, syn, fin, nack)
    ip_address_long = struct.unpack("!L", socket.inet_aton(ip_address))[0]
    # TODO Need checksum()
    rtp_header = struct.pack('!LLHBLH', seq_num, ack_num, window_size, flags, ip_address_long, port)
    addr = ip_address, port
    sock.sendto(rtp_header, addr)

def recv():
    packet = sock.recvfrom(buff_size)
    data = packet[0]
    rtp_header = struct.unpack('!LLHBLH',data)
    flags = rtp_header[3]
    ack, syn, fin, nack = unpack_bits(flags)


    #ip_address_old = struct.pack("!L", ip_address_long)


def pack_bits(ack, syn, fin, nack):

    bit_string = str(ack) + str(syn) + str(fin) + str(nack)
    bit_string = '0000' + bit_string # If you augment, it won't be correct, unless we want to put the flags in higher
    bit_string = int(bit_string, 2)

    return bit_string

def unpack_bits(bit_string):

    bit_string = format(bit_string, '08b')
    ack = int(bit_string[4])
    syn = int(bit_string[5])
    fin = int(bit_string[6])
    nack = int(bit_string[7])

    return ack, syn, fin, nack


def connect_timeout(args):
    pass


def connect(client_port, ip_address, net_emu_port):

    try:
        sock.bind(('', client_port))
    except socket.error, msg:
        print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()

    send(0, 1, 0, 0, ip_address, net_emu_port)
    recv()
    num_timeouts = 0
    timer = Timer(10, connect_timeout)
    #while True:
    #    data, addr = sock.recvfrom(buff_size)
    return True


def main(argv):
    if len(argv) != 3:
        print("Correct usage: FxA-Client X A P")
        sys.exit(1)

    client_port = argv[0]
    ip_address = argv[1]
    net_emu_port = argv[2]
    is_connected = False
    x = ''
    state = State.CLOSED
    seq_num = random.randint(0, 2**32-1)

    try:
        client_port = int(client_port)
    except ValueError:
        print('Invalid client port number %s' % argv[0])
        sys.exit(1)

    if client_port % 2 == 1:
        print('Client port number: %d was not even number' % client_port)
        sys.exit(1)

    try:
        # TODO check correct format for ip_address; UDP takes string
        ip_address = ip_address#socket.inet_aton(ip_address)
    except socket.error:
        print("Invalid IP notation: %s" % argv[1])
        sys.exit(1)
        # TODO check if port is open!

    try:
        net_emu_port = int(net_emu_port)
    except ValueError:
        print('Invalid NetEmu port number: %s' % argv[2])
        sys.exit(1)





    print('Command Options:')
    print('connect\t\t|\tConnects to the FxA-server')
    print('get F\t\t|\tRetrieve file F from FxA-server')
    print('post F\t\t|\tPushes file F to the FxA-server')
    print("window W\t|\tSets the maximum receiver's window size")
    print("disconnect\t|\tDisconnect from the FxA-server\n")

    while x != 'disconnect':
        x = raw_input('Please enter command:')
        if x == 'connect' and is_connected == False:
            is_connected = connect(client_port, ip_address, net_emu_port)
        elif x == 'connect' and is_connected == True:
            print ("Client already connected to server")
        elif x == 'disconnect':
            # TODO disconnect() call
            break
        else:
            y = x.split(" ")
            if y[0] == 'get':
                if len(y) != 2:
                    print("Invalid command: get requires secondary parameter")
                    continue
                if is_connected:
                    # TODO get()
                    print('get')
                else:
                    print('get not valid without existing connection')
            elif y[0] == 'post':
                if len(y) != 2:
                    print("Invalid command: post requires secondary parameter")
                    continue
                if is_connected:
                    # TODO post()
                    print('post')
                else:
                    print('post not valid without existing connection')
            elif y[0] == 'window':
                if len(y) != 2:
                    print("Invalid command: window requires secondary parameter")
                    continue
                try:
                    window_size = int(y[1])
                except ValueError:
                    print('Invalid window size (not a number): %s' % y[1])
                    continue
                # TODO window()
                print('window')
            else:
                print("Command not recognized")


class State:
    SYN_SENT = 1
    SYN_RECEIVED = 2
    SYN_SENT_HASH = 3
    ESTABLISHED = 4
    FIN_WAIT_1 = 5
    FIN_WAIT_2 = 6
    CLOSE_WAIT = 7
    CLOSING = 8
    LAST_ACK = 9
    TIME_WAIT = 10
    CLOSED = 11

    def __init__(self):
        pass


if __name__ == "__main__":

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        print 'Failed to create socket'
        sys.exit()

    main(sys.argv[1:])
