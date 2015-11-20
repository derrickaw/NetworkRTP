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
                # start connect
                try:
                    t_connect = threading.Thread(target=connect, args=())
                    t_connect.daemon = True
                    t_connect.start()
                except:
                    print "Error"
                t_connect.join()
                print "False"
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
            packet = sock.recvfrom(BUFFER_SIZE)
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
    global client_state_temp
    global server_window_size
    global client_port
    global server_seq_num
    global server_port
    global num_timeouts_syn_sent
    global num_timeouts_syn_ack_hash
    global client_timer
    global server_hash_challenge
    global client_state_master
    global is_connected

    while True:
        # Check if timeouts have reached the max limit; if so, return False
        if num_timeouts_syn_sent > TIMEOUT_MAX_LIMIT or num_timeouts_syn_ack_hash > TIMEOUT_MAX_LIMIT:
            client_timer.cancel()
            if is_debug:
                print "Connection process timed-out"
            is_connected = False
            break

        if client_state_temp == State.RCV:
            rtp_header, payload = recv()
            client_timer.cancel()
            # server_seq_num, server_ack_num, checksum, server_window_size, ack, syn, fin, nack, server_ip_address_long, \
            #     server_port = unpack_rtpheader(rtp_header)

            # Check checksum; if bad, drop packet, send nack, and go back to recv
            if not check_checksum(rtp_header.get_checksum(), rtp_header, payload):
                client_timer = threading.Timer(TIMEOUT_TIME, connect_timeout)
                client_timer.start()
                client_state_temp = State.RCV

                if is_debug:
                    print "Checksum checker detected error on challenge from server, sending NACK"
                send_nack()

            # If nack recv, send temp state to master state seen last
            elif rtp_header.get_nack():
                if client_state_master == State.SYN_SENT:
                    client_state_temp = State.SYN_SENT
                elif client_state_master == State.SYN_SENT_HASH:
                    client_state_temp = State.SYN_SENT_HASH

            # If syn and ack, then master and temp states change to SYN_SENT_HASH
            elif rtp_header.get_syn() and rtp_header.get_ack():
                server_hash_challenge = payload
                client_state_temp = State.SYN_SENT_HASH
                client_state_master = State.SYN_SENT_HASH

            # If not syn and ack, then master and temp states change to ESTABLISHED
            elif not rtp_header.get_syn() and rtp_header.get_ack():
                client_state_temp = State.ESTABLISHED
                client_state_master = State.ESTABLISHED
                if is_debug:
                    print "Received ACK from server, connection established"
                is_connected = True
                break

        # Send request to connect
        if client_state_temp == State.SYN_SENT:
            client_timer = threading.Timer(TIMEOUT_TIME, connect_timeout)
            client_timer.start()
            client_state_temp = State.RCV

            if is_debug:
                print "Sending initial SYN to server"
            send_syn()

        # Send hash_of_hash to finalize 4-way handshake
        if client_state_temp == State.SYN_SENT_HASH:
            client_timer = threading.Timer(TIMEOUT_TIME, connect_timeout)
            client_timer.start()
            client_state_temp = State.RCV

            if is_debug:
                print "Sending SYN + ACK + response"
            send_synack(server_hash_challenge)


def connect_timeout():
    global client_state_temp
    global num_timeouts_syn_sent
    global num_timeouts_syn_ack_hash

    if client_state_master == State.SYN_SENT:
        client_state_temp = State.SYN_SENT
        num_timeouts_syn_sent += 1
        return connect()
    elif client_state_master == State.SYN_SENT_HASH:
        client_state_temp = State.SYN_SENT_HASH
        num_timeouts_syn_ack_hash += 1
        return connect()



def get(filename):
    pass


def send_and_wait_for_ack(payload, num_timeouts):
    # Send out the packet
    send(0, 0, 0, 0, payload)
    packet = None
    try:
        # Wait until the process queue has a packet, block for TIMEOUT_TIME seconds
        packet = process_queue.get(True, TIMEOUT_TIME)
    except Queue.Empty:  # If after blocking there still was not a packet in the queue
        # If we have timed out TIMEOUT_MAX_LIMIT times, then cancel the operation
        if num_timeouts == TIMEOUT_MAX_LIMIT:
            return False
        else:
            # If we have timed out less than TIMEOUT_MAX_LIMIT times, then try again with num_timeouts incremented
            print('.'),
            send_and_wait_for_ack(payload, num_timeouts + 1)
    if packet.get_header().get_ip() == net_emu_ip_address_long and \
        packet.get_header().get_port() == net_emu_port and \
            packet.get_header().get_ack_num() == client_ack_num:
        pass


def post(filename):
    try:
        file_handle = open(filename, 'r')
    except IOError:
        print "Could not open file: {0}".format(filename)
        return
    del packet_list[:]  # clear out the list of packets
    file_size = os.stat(filename).st_size
    init_payload = 'POST|{0}|{1}'.format(filename, str(file_size))
    if not send_and_wait_for_ack(init_payload, 0):
        print 'Could not retrieve response, POST Failed'
        return

    file_handle.read(123)


def calc_client_seq_ack_nums(payload):
    global client_seq_num
    global client_ack_num

    client_seq_num = client_ack_num

    if len(payload) == 0:
        client_ack_num = client_seq_num + 1
    else:
        client_ack_num = client_seq_num + len(payload)


def send(ack, syn, fin, nack, payload):

    # Change sequence and acknowledge numbers to correct ones before sending to server
    calc_client_seq_ack_nums(payload)

    checksum = 0
    rtp_header_obj = RTPHeader(client_seq_num, server_ack_num, checksum, client_window_size, ack, syn, fin, nack,
                               CLIENT_IP_ADDRESS_LONG, client_port)
    packed_rtp_header = pack_rtpheader(rtp_header_obj)

    # if payload is not None:
    packet = packed_rtp_header + payload
    # else:
    #     packet = packed_rtp_header

    checksum = sum(bytearray(packet))

    rtp_header_obj = RTPHeader(client_seq_num, server_ack_num, checksum, client_window_size, ack, syn, fin, nack,
                               CLIENT_IP_ADDRESS_LONG, client_port)
    packed_rtp_header = pack_rtpheader(rtp_header_obj)

    # if payload is not None:
    packet = packed_rtp_header + payload
    # else:
    #     packet = packed_rtp_header
    if is_debug:
        print "Sending:"
        print '\tClient Seq Num:\t' + str(client_seq_num)
        print '\tClient ACK Num:\t' + str(client_ack_num)
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


def calc_server_seq_ack_nums(payload):
    global server_ack_num

    if len(payload) == 0:
        server_ack_num = server_seq_num + 1
    else:
        server_ack_num = server_seq_num + len(payload)



def recv():
    global server_seq_num
    global client_window_size

    recv_packet = sock.recvfrom(BUFFER_SIZE)
    packet = recv_packet[0]
    rtp_header = packet[0:21]
    rtp_header = unpack_rtpheader(rtp_header)
    payload = packet[21:]
    print 'Received Payload (may be corrupted):'
    print str(payload)
    calc_server_seq_ack_nums(payload)

    return rtp_header, payload


def pack_rtpheader(rtp_header):

    flags = pack_bits(rtp_header.get_ack(), rtp_header.get_syn(), rtp_header.get_fin(), rtp_header.get_nack())
    rtp_header = struct.pack('!LLHLBLH', rtp_header.get_seq_num(), rtp_header.get_ack_num(), rtp_header.get_checksum(),
                             rtp_header.get_window(), flags, rtp_header.get_ip(), rtp_header.get_port())

    return rtp_header


def unpack_rtpheader(packed_rtp_header):
    global server_window_size
    global server_seq_num
    global server_port

    unpacked_rtp_header = struct.unpack('!LLHLBLH', packed_rtp_header)  # 21 bytes

    server_seq_num = unpacked_rtp_header[0]
    client_ack_num_test = unpacked_rtp_header[1]
    checksum = unpacked_rtp_header[2]
    server_window_size = unpacked_rtp_header[3]
    flags = unpacked_rtp_header[4]
    ack, syn, fin, nack = unpack_bits(flags)
    server_ip_address_long = unpacked_rtp_header[5]
    server_port = unpacked_rtp_header[6]
    rtp_header_obj = RTPHeader(server_seq_num, client_ack_num_test, checksum, server_window_size, ack, syn, fin, nack,
                           server_ip_address_long, server_port)

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

    return rtp_header_obj


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


def check_checksum(checksum, rtp_header, payload):

    flags = pack_bits(rtp_header.get_ack(), rtp_header.get_syn(), rtp_header.get_fin(), rtp_header.get_nack())
    packed_checksum = struct.pack('!L', checksum)
    packed_rtp_header = struct.pack('!LLHLBLH', rtp_header.get_seq_num(), rtp_header.get_ack_num(), checksum,
                                    client_window_size, flags, CLIENT_IP_ADDRESS_LONG, client_port)

    data = packed_rtp_header + payload

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

    send(0, 1, 0, 0, CLIENT_EMPTY_PAYLOAD)


def send_synack(payload):

    if payload != CLIENT_EMPTY_PAYLOAD:
        payload = create_hash(payload)

    send(1, 1, 0, 0, payload)


def send_nack():
    send(0, 0, 0, 1, CLIENT_EMPTY_PAYLOAD)


def send_ack():
    send(1, 0, 0, 0, CLIENT_EMPTY_PAYLOAD)


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
    RCV = 11

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
    # Misc Global variables
    BUFFER_SIZE = 1045  # 21 bytes for rtp_header and 1024 bytes for payload
    is_debug = False

    # Client
    client_window_size = 1
    client_port = ''
    CLIENT_IP_ADDRESS = socket.gethostbyname(socket.gethostname())
    CLIENT_IP_ADDRESS_LONG = struct.unpack("!L", socket.inet_aton(CLIENT_IP_ADDRESS))[0]
    client_state_temp = State.SYN_SENT
    client_seq_num = 0  # random.randint(0, 2**32-1)
    client_ack_num = client_seq_num
    client_timer = ''
    CLIENT_EMPTY_PAYLOAD = ''
    num_timeouts_syn_sent = 0
    num_timeouts_syn_ack_hash = 0
    TIMEOUT_MAX_LIMIT = 3
    TIMEOUT_TIME = 5
    client_state_master = State.SYN_SENT
    packet_list = []

    # NetEmu
    net_emu_ip_address = ''
    net_emu_ip_address_long = ''
    net_emu_port = ''
    net_emu_addr = ''

    # Server
    server_IP_Address = ''
    server_port = ''
    server_seq_num = 0
    server_ack_num = 0
    server_window_size = 1
    server_hash_challenge = ''
    process_queue = Queue.Queue(maxsize=15000)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        print 'Failed to create socket'
        sys.exit()

    main(sys.argv[1:])
