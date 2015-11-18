import Queue
import hashlib
import os
import random
import re
import socket
import struct
import sys
import threading


# TODO: Pack Header '!LLHLBLH'


def main(argv):
    global client_port
    global net_emu_ip_address
    global net_emu_port
    global net_emu_addr
    global client_window_size
    global client_state
    global client_seq_num
    global is_debug

    if len(argv) < 3 or len(argv) > 4:
        print("Correct usage: FxA-Client X A P [-debug]")
        sys.exit(1)

    client_port = argv[0]
    net_emu_ip_address = argv[1]
    net_emu_port = argv[2]
    is_debug_arg = ''
    if len(argv) == 4:
        is_debug_arg = argv[3]
    is_connected = False
    command_input = ''

    # Check that entered client port is an integer
    try:
        client_port = int(client_port)
    except ValueError:
        print('Invalid client port number %s' % argv[0])
        sys.exit(1)

    # Check that client port is odd so that NetEmu can tell the difference between client and server
    if client_port % 2 == 1:
        print('Client port number: %d was not even number' % client_port)
        sys.exit(1)

    # Check that entered NetEmu IP address is in correct format
    try:
        socket.inet_aton(net_emu_ip_address)
        p = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
        if not p.match(net_emu_ip_address):
            raise socket.error()
    except socket.error:
        print("Invalid IP notation: %s" % argv[1])
        sys.exit(1)
        # TODO check if port is open!

    # Check that entered NetEmu port is an integer
    try:
        net_emu_port = int(net_emu_port)
    except ValueError:
        print('Invalid NetEmu port number: %s' % argv[2])
        sys.exit(1)

    if len(argv) == 4:
        if is_debug_arg.lower() == '-debug':
            is_debug = True
            print('Debug mode activated')
        else:
            print('Could not parse argument: %s' % argv[3])
            sys.exit(1)

    # Create address for sending to NetEmu
    net_emu_addr = net_emu_ip_address, net_emu_port

    # Bind to client port
    try:
        sock.bind(('', client_port))
    except socket.error, msg:
        print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit(1)


    # start packet collection and start processing queue
    # try:
    #     t_recv = threading.Thread(target=recv_packet, args=())
    #     t_recv.daemon = True
    #     t_recv.start()
    #     t_proc = threading.Thread(target=proc_packet, args=())
    #     t_proc.daemon = True
    #     t_proc.start()
    # except:
    #     print "Error"


    # Setup for Client Command Instructions
    print('Command Options:')
    print('connect\t\t|\tConnects to the FxA-server')
    print('get F\t\t|\tRetrieve file F from FxA-server')
    print('post F\t\t|\tPushes file F to the FxA-server')
    print("window W\t|\tSets the maximum receiver's window size")
    print("disconnect\t|\tDisconnect from the FxA-server\n")

    while command_input != 'disconnect':
        command_input = raw_input('Please enter command:')
        if command_input == 'connect':
            if not is_connected:
                is_connected = connect()
            else:
                print ("Client already connected to server")
        elif command_input == 'disconnect':
            # TODO disconnect() call
            break
        else:
            command_input_split = command_input.split(" ")
            if command_input_split[0] == 'get':
                if len(command_input_split) != 2:
                    print("Invalid command: get requires secondary parameter")
                    continue
                if is_connected:
                    get(command_input_split[1])
                else:
                    print('get not valid without existing connection')
            elif command_input_split[0] == 'post':
                if len(command_input_split) != 2:
                    print("Invalid command: post requires secondary parameter")
                    continue
                if is_connected:
                    post(command_input_split[1])
                else:
                    print('post not valid without existing connection')
            elif command_input_split[0] == 'window':
                if len(command_input_split) != 2:
                    print("Invalid command: window requires secondary parameter")
                    continue
                try:
                    window_size = int(command_input_split[1])
                except ValueError:
                    print('Invalid window size (not a number): %s' % command_input_split[1])
                    continue
                # TODO window()
                print('window')
            else:
                print("Command not recognized")

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
            recv_packet = process_queue.get()
            packet = recv_packet[0]
            rtp_header = packet[0:21]
            payload = packet[21:]

            client_seq_num, client_ack_num, checksum, client_window_size, ack, syn, fin, nack, client_ip_address_long, \
                client_port = unpack_rtpheader(rtp_header)

            # # Check checksum; if bad, drop packet and send nack; if good, proceed, otherwise,
            # if not check_checksum(checksum, packet):
            #     if is_debug:
            #         print 'Checksum Incorrect, sending NACK'
            #     send_nack()
            # # Checksum is good; let's roll with connection setup or processing command
            # else:
            #     if is_debug:
            #         print 'Checksum Correct'
            #         print 'Received Payload:'
            #         print str(payload)
            #     # Connection setup
            #     if (syn and not ack) or (syn and ack): #and not # TODO:
            #         connection_setup(client_seq_num, client_ack_num, client_window_size, ack, syn, fin, nack,
            #                          client_ip_address_long, client_port, payload)
            #     # Check client list for existing connection and then start get or post
            #     elif not syn and not ack and not fin:
            #         client = check_client_list(client_ip_address_long, client_port)
            #
            #         # TODO - Look inside packet for command



def connect():
    global client_state
    global server_window_size
    global client_port
    global server_seq_num
    global server_port
    global num_timeouts_syn_sent
    global num_timeouts_syn_ack_hash
    global timer
    global packet_op
    global rtp_header
    global payload


    while True:
        # Send request to connect or if packet was corrupted, dropped, or etc; send again
        if client_state == State.CLOSED:
            timer = threading.Timer(10, connect_timeout)
            timer.start()
            client_state = State.SYN_SENT
            packet_op = Data.RECV
            if is_debug:
                print "Sending initial SYN to server"
            send_syn()
        # Receive syn + ack + challenge back from server
        if client_state == State.SYN_SENT and packet_op == Data.RECV:
            rtp_header, payload = recv()
            timer.cancel()
            server_seq_num, server_ack_num, checksum, server_window_size, ack, syn, fin, nack, server_ip_address_long, \
                server_port = unpack_rtpheader(rtp_header)

            # Received nack from server; change state back to closed and resend SYN
            if nack:
                client_state = State.CLOSED
            else:
                # Check checksum; if bad, drop packet, send nack, and go back to recv to obtain new packet from server
                if not check_checksum(checksum, rtp_header + payload):
                    timer = threading.Timer(10, connect())
                    timer.start()
                    if is_debug:
                        print "Checksum checker detected error on challenge from server, sending NACK"
                    send_nack()

                # Checksum is good; send hash_of_hash to complete challenge
                else:
                    client_state = State.SYN_SENT_HASH
                    packet_op = Data.SEND


        # Received good checksum and
        if client_state == State.SYN_SENT_HASH and packet_op == Data.SEND:
            timer = threading.Timer(10, connect_timeout())
            timer.start()

            if is_debug:
                print "Received challenge from server sending SYN + ACK + response"
            send_synack(payload)



        # Receive ack from hash challenge from server
        if client_state == State.SYN_SENT_HASH and packet_op == Data.RECV:
            # Receive ack from hash challenge from server
            rtp_header, payload = recv()
            timer.cancel()
            server_seq_num, server_ack_num, checksum, server_window_size, ack, syn, fin, nack, server_ip_address_long, \
                server_port = unpack_rtpheader(rtp_header)

            timer = threading.Timer(10, connect)
            timer.start()
            # Check checksum; if bad, drop packet and send nack
            if not check_checksum(checksum, rtp_header + payload):
                if is_debug:
                    print "Checksum checker detected error on ACK from server, sending NACK"
                send_nack()
                #return False

            # Checksum is good; done
            elif ack:
                timer.cancel()
                if is_debug:
                    print "Received ACK from server, connection established"
                return True
            # Checksum is good, but nack was sent; resend synackhash
            elif nack:
                send_synack(payload)

        # Check if timeouts have reached the max limit; if so, return False
        if num_timeouts_syn_sent > timeout_maxlimit or num_timeouts_syn_ack_hash > timeout_maxlimit:
            if is_debug:
                print "Connection process timed-out"
            return False

        # Receive syn + ack + challenge
        #ack_num, checksum, client_window_size, ack, syn, fin, nack, client_ip_address_long, client_port = recv()
        #num_timeouts = 0
        #timer = threading.Timer(10, connect_timeout)

        #return True


def connect_timeout():
    global client_state
    global transfer_data

    if client_state == State.SYN_SENT:
        client_state = State.CLOSED
        connect()
    if client_state == State.SYN_SENT_HASH:
        pass


def get(filename):
    pass


def post(filename):
    try:
        file_handle = open(filename, 'r')
    except IOError:
        print "Could not open file: {0}".format(filename)
        return
    file_size = os.stat(filename).st_size
    init_payload = 'POST|{0}|{1}'.format(filename, str(file_size))
    file_handle.read(123)


def send(ack_num, ack, syn, fin, nack, payload):
    global client_seq_num


    checksum = 0
    rtp_header = pack_rtpheader(seq_num, ack_num, checksum, ack, syn, fin, nack)

    if payload is not None:
        packet = rtp_header + payload
    else:
        packet = rtp_header

    checksum = sum(bytearray(packet))
 
    rtp_header = pack_rtpheader(seq_num, ack_num, checksum, ack, syn, fin, nack)

    if payload is not None:
        packet = rtp_header + payload
    else:
        packet = rtp_header
    if is_debug:
        print "Sending:"
        print '\tClient Seq Num:\t' + str(seq_num)
        print '\tClient ACK Num:\t' + str(ack_num)
        print '\tChecksum:\t' + str(checksum)
        print '\tWindow:\t\t' + str(client_window_size)
        print '\tACK:\t\t' + str(ack)
        print '\tSYN:\t\t' + str(syn)
        print '\tFIN:\t\t' + str(fin)
        print '\tNACK:\t\t' + str(nack)
        print '\tClient IP Long:\t' + str(CLIENT_IP_ADDRESS_LONG)
        print '\tClient Port:\t' + str(client_port)
        print '\tPayload:\t' + str(payload)
        print '\tSze-Pyld:\t' + str(payload)

    sock.sendto(packet, net_emu_addr)


def recv():
    global server_seq_num
    global client_window_size

    recv_packet = sock.recvfrom(buff_size)
    packet = recv_packet[0]
    rtp_header = packet[0:21]
    payload = packet[21:]
    print 'Received Payload (may be corrupted):'
    print str(payload)

    return rtp_header, payload


def pack_rtpheader(seq_num, ack_num, checksum, ack, syn, fin, nack):

    flags = pack_bits(ack, syn, fin, nack)
    rtp_header = struct.pack('!LLHLBLH', seq_num, ack_num, checksum, client_window_size, flags, CLIENT_IP_ADDRESS_LONG,
                             client_port)

    return rtp_header


def unpack_rtpheader(rtp_header):
    global server_window_size
    global server_seq_num
    global server_port

    rtp_header = struct.unpack('!LLHLBLH', rtp_header)  # 21 bytes

    server_seq_num = rtp_header[0]
    server_ack_num = rtp_header[1]
    checksum = rtp_header[2]
    server_window_size = rtp_header[3]
    flags = rtp_header[4]
    ack, syn, fin, nack = unpack_bits(flags)
    server_ip_address_long = rtp_header[5]
    server_port = rtp_header[6]

    if is_debug:
        print "Unpacking Header:"
        print '\tServer Seq Num:\t' + str(server_seq_num)
        print '\tServer ACK Num:\t' + str(server_ack_num)
        print '\tChecksum:\t' + str(checksum)
        print '\tServer Window:\t' + str(server_window_size)
        print '\tACK:\t\t' + str(ack)
        print '\tSYN:\t\t' + str(syn)
        print '\tFIN:\t\t' + str(fin)
        print '\tNACK:\t\t' + str(nack)
        print '\tSer. IP Long:\t' + str(server_ip_address_long)
        print '\tSer. Port:\t' + str(server_port)

    return server_seq_num, server_ack_num, checksum, server_window_size, ack, syn, fin, nack, server_ip_address_long,\
        server_port


def pack_bits(ack, syn, fin, nack):

    bit_string = str(ack) + str(syn) + str(fin) + str(nack)
    bit_string = '0000' + bit_string  # If you augment, it won't be correct, unless we want to put the flags in higher
    bit_string = int(bit_string, 2)

    return bit_string


def unpack_bits(bit_string):

    bit_string = format(bit_string, '08b')
    ack = int(bit_string[4])
    syn = int(bit_string[5])
    fin = int(bit_string[6])
    nack = int(bit_string[7])

    return ack, syn, fin, nack


def check_checksum(checksum, data):

    packed_checksum = struct.pack('!L', checksum)
    new_checksum = sum(bytearray(data))
    new_checksum -= sum(bytearray(packed_checksum))

    if checksum == new_checksum:
        if is_debug:
            print 'Checksum Correct'
        return True
    else:
        if is_debug:
            print 'Checksum Incorrect'
        return False








def create_hash(hash_challenge):
    hash_of_hash = hashlib.sha224(hash_challenge).hexdigest()
    return hash_of_hash


def send_syn():
    global num_timeouts_syn_sent

    num_timeouts_syn_sent += 1
    send(client_seq_num, client_ack_num, 0, 1, 0, 0, '')


def send_synack(payload):
    global  num_timeouts_syn_ack_hash

    num_timeouts_syn_ack_hash += 1

    if payload is None:
        payload = ''
    else:
        hash_of_hash = create_hash(payload)

    send(client_seq_num, client_ack_num, 1, 1, 0, 0, payload)


def send_nack():
    send(client_seq_num, client_ack_num, 0, 0, 0, 1, '')


def send_ack():
    send(client_seq_num, client_ack_num, 1, 0, 0, 0, '')


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

class Data:
    SEND = 1
    RECV = 2

    def __init__(self):
        pass

class RTPHeader:
    def __init__(self, seq_num, ack_num, checksum, window, ack, syn, fin, nack, ip, port):
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.checksum = checksum
        self.window = window
        self.ack = ack
        self.syn = syn
        self.fin = fin
        self.nack = nack
        self.ip = ip
        self.port = port

    def get_seq_num(self):
        return self.seq_num

    def get_ack_num(self):
        return self.ack_num

    def get_checksum(self):
        return self.checksum

    def get_window(self):
        return self.window

    def get_ack(self):
        return self.ack

    def get_syn(self):
        return self.syn

    def get_fin(self):
        return self.fin

    def get_nack(self):
        return self.nack

    def get_ip(self):
        return self.ip

    def get_port(self):
        return self.port


class Packet:
    def __init__(self, header, payload):
        self.header = header
        self.payload = payload

    def get_header(self):
        return self.header

    def get_payload(self):
        return self.payload

if __name__ == "__main__":

    client_window_size = 1
    buff_size = 1024
    client_port = ''
    CLIENT_IP_ADDRESS = socket.gethostbyname(socket.gethostname())
    CLIENT_IP_ADDRESS_LONG = struct.unpack("!L", socket.inet_aton(CLIENT_IP_ADDRESS))[0]
    net_emu_ip_address = ''
    net_emu_ip_address_long = ''
    net_emu_port = ''
    net_emu_addr = ''
    client_state = State.CLOSED
    client_seq_num = random.randint(0, 2**32-1)
    client_ack_num = client_seq_num
    server_seq_num = 0
    server_window_size = 1
    process_queue = Queue.Queue(maxsize=15000)
    is_debug = False
    timer = ''
    num_timeouts_syn_sent = 0
    num_timeouts_syn_ack_hash = 0
    timeout_maxlimit = 10
    packet_op = Data.SEND
    rtp_header = ''
    payload = ''

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        print 'Failed to create socket'
        sys.exit()

    main(sys.argv[1:])
