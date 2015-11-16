import hashlib
import random
import socket
import struct
import sys
import threading
import Queue
from threading import Timer



def main(argv):
    global server_port
    global net_emu_ip_address
    global net_emu_port
    global net_emu_addr

    if len(argv) != 3:
        print("Correct usage: FxA-Server X A P")
        sys.exit(1)

    # Save user input
    server_port = argv[0]
    net_emu_ip_address = argv[1]
    net_emu_port = argv[2]

    # Check Port is an int
    try:
        server_port = int(server_port)
    except ValueError:
        print('Invalid server port number %s' % argv[0])
        sys.exit(1)

    # Check server port is even for correct interaction with NetEmu
    if server_port % 2 == 0:
        print('Server port number: %d was not an odd number' % server_port)
        sys.exit(1)

    # Check IP address is in correct notation
    try:
        # TODO double check all IP addresses are caught
        socket.inet_aton(net_emu_ip_address)
    except socket.error:
        print("Invalid IP notation: %s" % argv[1])
        sys.exit(1)
        # TODO check if port is open!

    # Check port number is an int
    try:
        net_emu_port = int(net_emu_port)
    except ValueError:
        print('Invalid NetEmu port number: %s' % argv[2])
        sys.exit(1)

    # Create address for sending to NetEmu
    net_emu_addr = net_emu_ip_address, net_emu_port

    # Bind to server port
    sock.bind(('', server_port))

    # start packet collection and start processing queue
    try:
        t_recv = threading.Thread(target=recv_packet,args=())
        t_recv.daemon = True
        t_recv.start()
        t_proc = threading.Thread(target=proc_packet,args=())
        t_proc.daemon = True
        t_proc.start()
    except:
        print "Error"



    # Setup for Server Command Instructions
    print('Command Options:')
    print("window W\t|\tSets the maximum receiver's window size")
    print("terminate\t|\tShut-down FxA-Server gracefully\n")

    # Loop for commands from server user
    while True:
        command_input = str(raw_input('Please enter command:'))
        if command_input == 'terminate':
            # TODO terminate() call
            break
        else:
            parsed_command_input = command_input.split(" ")
            if parsed_command_input[0] == 'window':
                if len(parsed_command_input) != 2:
                    print("Invalid command: window requires secondary parameter")
                    continue
                try:
                    window_size = int(parsed_command_input[1])
                except ValueError:
                    print('Invalid window size (not a number): %s' % parsed_command_input[1])
                    continue
                # TODO window()
                print('window')
            else:
                print("Command not recognized")

    # Closing server and socket
    print("Server closing")
    sock.close()

    #t_term.set()




def recv_packet():
    while True:
        try:
            packet = sock.recvfrom(buff_size)
            process_queue.put(packet)
        except socket.error, msg:
            continue

def proc_packet():
    while True:
        while not process_queue.empty():
            packet = process_queue.get()
            data = packet[0]
            #print len(data)

            seq_num, ack_num, client_window_size, ack, syn, fin, nack, client_ip_address_long, client_port = \
                unpack_rtpheader(data)

            # Connection setup
            if (syn and not ack) or (syn and ack):
                t_connection = threading.Thread(target=connection_setup,args=(seq_num, ack_num, client_window_size,
                                                ack, syn, fin, nack, client_ip_address_long, client_port))
                t_connection.daemon = True
                t_connection.start()

            # TODO How will we tell the server that we want to pull down or upload a file?




def pack_rtpheader(seq_num, ack_num, ack, syn, fin, nack):

    flags = pack_bits(ack, syn, fin, nack)
    print flags
    rtp_header = struct.pack('!LLHBLH', seq_num, ack_num, server_window_size, flags, SERVER_IP_ADDRESS_LONG,
                             server_port)

    return rtp_header


def unpack_rtpheader(rtp_header):
    rtp_header = struct.unpack('!LLHBLH', rtp_header)

    seq_num = rtp_header[0]
    ack_num = rtp_header[1]
    client_window_size = rtp_header[2]
    flags = rtp_header[3]
    ack, syn, fin, nack = unpack_bits(flags)
    client_ip_address_long = rtp_header[4]
    client_port = rtp_header[5]

    return seq_num, ack_num, client_window_size, ack, syn, fin, nack, client_ip_address_long, client_port


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


def connection_setup(seq_num, ack_num, client_window_size, ack, syn, fin, nack, client_ip_address_long, client_port):

    packed_ip = struct.pack('!L', client_ip_address_long)
    client_ip_address = socket.inet_ntoa(packed_ip)         # TODO do we want to store IP or IP long?

    # Check client list for existing connection
    client = check_client_list(client_ip_address, client_port)

    # Start new connection to client and send client SYN, ACK, CHALLENGE
    if syn and not ack and not fin and client is None:
        client = Connection(client_ip_address, client_port, seq_num)
        clientList.append(client)
        send(client, seq_num, ack_num, 1, 1, 0, 0) # TODO
    # Complete 4-way handshake by by receiving challenge and sending ACK
    else:
        client.update_on_receive(syn, ack, fin)


def check_client_list(client_ip_address, client_port):
    for i in range(len(clientList)):
        if clientList[i].get_sender_ip() == client_ip_address and clientList[i].get_sender_port() == client_port:
            return clientList[i]
    return None

def create_hash(random_int):
    random_string = str(random_int)
    hash = hashlib.sha224(random_string).hexdigest()

    return hash

def send(client, seq_num, ack_num, ack, syn, fin, nack):

    # TODO Need checksum()
    print client.get_hash()
    rtp_header = pack_rtpheader(seq_num, ack_num, ack, syn, fin, nack)
    payload = pack_payload(rtp_header, client.get_hash())
    sock.sendto(payload, net_emu_addr)


def timeout(args):
    pass

def pack_payload(rtp_header, data):
    payload = rtp_header + data
    # TODO probably need to do more than this when we actually send the file

    return payload



def acknowledge(seq_num, ack_num, ack, syn, fin, nack):
    rtp_header = pack_rtpheader(seq_num, ack_num, ack, syn, fin, nack)
    sock.sendto(rtp_header, net_emu_addr)


def checkhash():
    pass


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

class Connection:

    def __init__(self, client_ip, client_port, seq_num):
        self.state = State.SYN_RECEIVED
        self.client_ip = client_ip
        self.client_port = client_port
        self.timer = Timer(10, timeout)
        self.timer.start()
        #self.random_num = random.randint(0,2**64-1)
        self.hash = create_hash(random.randint(0,2**64-1))
        self.seq_num = seq_num

    def get_sender_ip(self):
        return self.sender_ip

    def get_sender_port(self):
        return self.sender_port

    def get_hash(self):
        return self.hash

    def get_seq_num(self):
        return self.seq_num

    def increase_seq_num(self, amount):
        self.seq_num += amount

    def update_on_receive(self, syn, ack, fin):
        self.timer.cancel()

        if self.state == State.SYN_RECEIVED:
            if syn and ack and not fin:
                if checkhash():
                    self.state = State.ESTABLISHED
                    acknowledge()
                else:
                    self.state = State.CLOSED
        elif self.state == State.ESTABLISHED:
            if not syn and not ack and fin:
                self.state = State.CLOSE_WAIT
                acknowledge()
        elif self.state == State.LAST_ACK:
            if not syn and ack and not fin:
                self.state = State.CLOSED
        elif self.state == State.FIN_WAIT_1:
            if not syn and not ack and fin:
                acknowledge()
                self.state = State.CLOSING
            if not syn and ack and not fin:
                self.state = State.FIN_WAIT_2
            if not syn and ack and fin:
                acknowledge()
                self.state = State.TIME_WAIT
        elif self.state == State.FIN_WAIT_2:
            if not syn and not ack and fin:
                acknowledge()
                self.state = State.TIME_WAIT
        elif self.state == State.CLOSING:
            if not syn and ack and not fin:
                self.state = State.TIME_WAIT
        else:
            print('state not valid')

        self.timer = Timer(10, timeout)
        self.timer.start()


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
    # Global variables
    buff_size = 1024
    server_window_size = 0
    terminate = False
    process_queue = Queue.Queue(maxsize=15000)
    #t_term = threading.Event()
    clientList = []
    server_port = ''
    SERVER_IP_ADDRESS = socket.gethostbyname(socket.gethostname())
    SERVER_IP_ADDRESS_LONG = struct.unpack("!L", socket.inet_aton(SERVER_IP_ADDRESS))[0]
    net_emu_ip_address = ''
    net_emu_ip_address_long = ''
    net_emu_port = ''
    net_emu_addr = ''

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        print 'Failed to create socket'
        sys.exit()


    main(sys.argv[1:])
