import Queue
import datetime
import hashlib
import random
import re
import socket
import struct
import sys
import threading
import time


# GET|FILENAME - CLIENT
#     Exists --- GET|FILENAME|<# of packets> ACK - SERVER
#     Not Exists --- GET|FILENOTFOUND|0 ACK - SERVER
# DATA - SERVER
# ACK - CLIENT
# ...
# ACK - CLIENT (PEACEFUL CLOSE)

# POST|FILENAME|<# of packets> - CLIENT
# ACK - SERVER
# DATA - CLIENT
# ACK - SERVER
# DATA - CLIENT
# ...
# ACK -SERVER

# Todo - How do we handle disconnect during file transfer; just block?


def main(argv):
    global server_port
    global net_emu_ip_address
    global net_emu_port
    global net_emu_addr
    global server_window_size
    global is_debug

    if len(argv) < 3 or len(argv) > 4:
        print("Correct usage: FxA-Server X A P [-debug]")
        sys.exit(1)

    # Save user input
    server_port = argv[0]
    net_emu_ip_address = argv[1]
    net_emu_port = argv[2]
    is_debug_arg = ''
    if len(argv) == 4:
        is_debug_arg = argv[3]

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
        socket.inet_aton(net_emu_ip_address)
        p = re.compile('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
        if not p.match(net_emu_ip_address):
            raise socket.error()
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

    if len(argv) == 4:
        if is_debug_arg.lower() == '-debug':
            is_debug = True
            print('Debug mode activated')
        else:
            print('Could not parse argument: %s' % argv[3])
            sys.exit(1)

    # Create address for sending to NetEmu
    net_emu_addr = net_emu_ip_address, net_emu_port

    # Bind to server port
    try:
        sock.bind(('', server_port))
    except socket.error, msg:
        print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit(1)

    # start packet collection and start processing queue
    try:
        t_recv = threading.Thread(target=recv_packet, args=())
        t_recv.daemon = True
        t_recv.start()
        t_proc = threading.Thread(target=proc_packet, args=())
        t_proc.daemon = True
        t_proc.start()
        # Probably not thread safe and shouldn't be done; lets just check for State.CLOSED instead
        # t_clear_clients = threading.Thread(target=clear_clients, args=())
        # t_clear_clients.daemon = True
        # t_clear_clients.start()
    except RuntimeError:
        print "Error creating/starting client slave thread(s)"

    # Setup for Server Command Instructions
    print "*" * 80
    print('Command Options:')
    print("window W\t|\tSets the maximum receiver's window size")
    print("terminate\t|\tShut-down FxA-Server gracefully")
    print "*" * 80
    print

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
                    server_window_size = int(parsed_command_input[1])
                except ValueError:
                    print('Invalid window size (not a number): %s' % parsed_command_input[1])
                    continue
            else:
                print("Command not recognized")

    # Closing server and socket
    print("Server closing")
    sock.close()


def recv_packet():
    global clientList
    global client_list_lock

    while True:
        try:
            # Obtain packet from buffer and process by breaking up into rtp_header and payload
            packet_recv = sock.recvfrom(BUFFER_SIZE)
            packet = packet_recv[0]
            rtp_header = packet[0:21]
            rtp_header = unpack_rtpheader(rtp_header)
            payload = packet[21:]

            if check_checksum(rtp_header.get_checksum(), rtp_header, payload):
                # Checksum is good
                if is_debug:
                    print 'Received Payload:'
                    print str(payload)

                # Check to see if client exists
                client_loc = check_client_list(rtp_header.get_ip(), rtp_header.get_port())

                # Update client window size
                if client_loc is not None:
                    with client_list_lock:
                        clientList[client_loc].window_size = rtp_header.get_window()
                # Enqueue packet to main buffer queue
                processed_packet = Packet(rtp_header, payload)
                process_queue.put(processed_packet)

        except socket.error, msg:
            continue


# def check_server_ack_num(client_loc, rtp_header):
#     global clientList
#     global client_list_lock
#
#     client_list_lock.acquire()
#     if clientList[client_loc].get_server_ack_num() == rtp_header.get_ack_num():
#         client_list_lock.release()
#         return True
#     client_list_lock.release()
#     return False


def proc_packet():
    global clientList
    global client_list_lock

    while True:
        while not process_queue.empty():

            if is_debug:
                print 'Processing Received Data'
            packet = process_queue.get()
            rtp_header = packet.get_header()
            payload = packet.get_payload()

            # Check to see if client exists or needs to setup
            client_loc = check_client_list(rtp_header.get_ip(), rtp_header.get_port())

            # Client doesn't exist; create client, append client to clientList, and start up client thread
            if client_loc is None:
                client = Connection(rtp_header.get_seq_num(), rtp_header.get_window(), rtp_header.get_ack(),
                                    rtp_header.get_syn(), rtp_header.get_fin(), rtp_header.get_nack(),
                                    rtp_header.get_ip(), rtp_header.get_port())

                client_ip_address = socket.inet_ntoa(struct.pack("!L", rtp_header.get_ip()))
                print "\nConnection with client %s %s is being established..." % (client_ip_address,
                                                                                  rtp_header.get_port())

                with client_list_lock:
                    clientList.append(client)
                client_loc = len(clientList) - 1

                client_t = threading.Thread(target=client_thread, args=(client_loc,))  # State.SYN_SENT, 0))
                client_t.daemon = True
                client_t.start()

            with client_list_lock:
                clientList[client_loc].mailbox.put(packet)


def client_thread(client_loc):
    timeout = 0

    while True:
        try:
            # Wait until the process queue has a packet, block for TIMEOUT_TIME seconds
            packet = clientList[client_loc].mailbox.get(True, TIMEOUT_TIME)
            # print clientList[client_loc].mailbox.qsize()

        except Queue.Empty:  # If after blocking there still was not a packet in the queue
            if timeout > TIME_MAX:
                client_ip_address = socket.inet_ntoa(struct.pack("!L", clientList[client_loc].client_ip))
                client_port = clientList[client_loc].client_port
                # Todo - Call disconnect
                print "Client %s %s was inactive...disconnected" % (client_ip_address, client_port)
                break
            else:
                timeout += TIMEOUT_TIME
                continue

        timeout = 0

        rtp_header = packet.get_header()
        payload = packet.get_payload()

        print rtp_header.get_seq_num()
        # Check for payload commands for GET or POST
        payload_split = check_for_get_or_post_request(payload)

        # Client calls a GET or POST command
        if payload_split is not None:

            # GET Command
            if payload_split[0] == 'GET':
                if is_debug:
                    print 'GET'
                get_t = threading.Thread(target=get, args=(payload_split[1], clientList[client_loc], packet,))
                get_t.daemon = True
                get_t.start()
                get_t.join()

            # POST Command
            elif 'POST' == payload_split[0]:
                if is_debug:
                    print 'POST'
                post_t = threading.Thread(target=post, args=(client_loc,))
                post_t.daemon = True
                post_t.start()
                post_t.join()

        # TODO - COMPLETE CONNECT AND DISCONNECT INSIDE HERE

        # Connection setup
        with client_list_lock:
            if rtp_header.get_syn() and not rtp_header.get_ack():
                if check_packet_match_ack_nums(client_loc, rtp_header):
                    clientList[client_loc].calc_client_server_recv_seq_ack_nums(payload)
                    clientList[client_loc].update_on_receive(rtp_header.get_ack(), rtp_header.get_syn(),
                                                             rtp_header.get_fin(), rtp_header.get_nack(), client_loc)

            elif rtp_header.get_syn() and rtp_header.get_ack():
                if check_packet_match_ack_nums(client_loc, rtp_header):
                    clientList[client_loc].client_seq_num = rtp_header.get_seq_num()
                    clientList[client_loc].calc_client_server_recv_seq_ack_nums(payload)
                    clientList[client_loc].hash_from_client = payload
                    clientList[client_loc].update_on_receive(rtp_header.get_ack(), rtp_header.get_syn(),
                                                             rtp_header.get_fin(), rtp_header.get_nack(), client_loc)

            # Disconnect is in operation
            elif rtp_header.get_fin():
                if check_packet_match_ack_nums(client_loc, rtp_header):
                    clientList[client_loc].calc_client_server_recv_seq_ack_nums(payload)
                    disconnect_t = threading.Thread(target=clientList[client_loc].update_on_receive, args=(
                                                    rtp_header.get_ack(), rtp_header.get_syn(), rtp_header.get_fin(),
                                                    rtp_header.get_nack(), client_loc))
                    disconnect_t.daemon = True
                    disconnect_t.start()
                    disconnect_t.join()
                # clientList[client_loc].update_on_receive(rtp_header.get_ack(), rtp_header.get_syn(),
                #                                          rtp_header.get_fin(), rtp_header.get_nack(), client_loc)

def check_packet_match_ack_nums(client_loc, rtp_header):

    # Check server ack number matches seq number + payload
    if clientList[client_loc].server_ack_num == rtp_header.get_ack_num() or rtp_header.get_ack_num() == 0:
        return True
    return False


def check_for_get_or_post_request(payload):
    if len(payload) > 0:
        payload_split = payload.split('|')
        if payload_split[0] == 'GET' or payload_split[0] == 'POST':
            return payload_split
    return None


# def check_packet_seq_ack_nums(client_loc, rtp_header):
#     # First compare calculated server_seq_nums to recv server_seq_num
#     client_seq_num_correct = False
#     with client_list_lock:
#         if clientList[client_loc].get_client_seq_num() == rtp_header.get_seq_num():
#             client_seq_num_correct = True
#
#     # Second check client ack number matches seq number
#     server_ack_num_correct = False
#     with client_list_lock:
#         if clientList[client_loc].get_server_ack_num() == rtp_header.get_ack_num():
#             server_ack_num_correct = True
#
#     return client_seq_num_correct and server_ack_num_correct


def clear_clients():
    while True:
        with client_list_lock:
            for i in range(len(clientList)):
                if clientList[i].get_client_state() == State.CLOSED:
                    if is_debug:
                        print 'Client in closed state found in connection list that needs deleting'
                    # Todo - This is probably not thread safe; Should we just change IP address to 0 and leave in there?
                    clientList.remove(i)

        # wake up every five seconds and check the list
        time.sleep(5)


# def current_window_size():
#     global server_window_size
#
#     server_window_size = QUEUE_MAX_SIZE - process_queue.qsize()

def send(server_seq_num, client_ack_num, ack, syn, fin, nack, payload):
    # Calculate checksum on rtp_header and payload with a blank checksum
    checksum = 0
    rtp_header_obj = RTPHeader(server_seq_num, client_ack_num, checksum, server_window_size, ack, syn, fin, nack,
                               SERVER_IP_ADDRESS_LONG, server_port)
    packed_rtp_header = pack_rtpheader(rtp_header_obj)
    packet = packed_rtp_header + payload
    checksum = sum(bytearray(packet))

    # Install checksum into rtp_header and package up with payload
    rtp_header_obj = RTPHeader(server_seq_num, client_ack_num, checksum, server_window_size, ack, syn, fin, nack,
                               SERVER_IP_ADDRESS_LONG, server_port)
    packed_rtp_header = pack_rtpheader(rtp_header_obj)
    packet = packed_rtp_header + payload

    if is_debug:
        print "Sending:"
        print '\tServer Seq Num:\t' + str(server_seq_num)
        print '\tClient ACK Num:\t' + str(client_ack_num)
        print '\tChecksum:\t' + str(checksum)
        print '\tServer Window:\t' + str(server_window_size)
        print '\tACK:\t\t' + str(ack)
        print '\tSYN:\t\t' + str(syn)
        print '\tFIN:\t\t' + str(fin)
        print '\tNACK:\t\t' + str(nack)
        print '\tServer IP Long:\t' + str(SERVER_IP_ADDRESS_LONG)
        print '\tServer Port:\t' + str(server_port)
        print '\tPayload:\t' + str(payload)
        print '\tSze-Pyld:\t' + str(len(payload))

    sock.sendto(packet, net_emu_addr)


def pack_rtpheader(rtp_header):
    flags = pack_bits(rtp_header.get_ack(), rtp_header.get_syn(), rtp_header.get_fin(), rtp_header.get_nack())
    rtp_header = struct.pack('!LLHLBLH', rtp_header.get_seq_num(), rtp_header.get_ack_num(), rtp_header.get_checksum(),
                             rtp_header.get_window(), flags, rtp_header.get_ip(), rtp_header.get_port())

    return rtp_header


def check_checksum(checksum, rtp_header, payload):
    flags = pack_bits(rtp_header.get_ack(), rtp_header.get_syn(), rtp_header.get_fin(), rtp_header.get_nack())
    packed_checksum = struct.pack('!L', checksum)
    packed_rtp_header = struct.pack('!LLHLBLH', rtp_header.get_seq_num(), rtp_header.get_ack_num(),
                                    rtp_header.get_checksum(), rtp_header.get_window(), flags, rtp_header.get_ip(),
                                    rtp_header.get_port())

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


def unpack_rtpheader(packed_rtp_header):
    unpacked_rtp_header = struct.unpack('!LLHLBLH', packed_rtp_header)  # 21 bytes

    client_seq_num = unpacked_rtp_header[0]
    server_ack_num = unpacked_rtp_header[1]
    checksum = unpacked_rtp_header[2]
    client_window_size = unpacked_rtp_header[3]
    flags = unpacked_rtp_header[4]
    ack, syn, fin, nack = unpack_bits(flags)
    client_ip_address_long = unpacked_rtp_header[5]
    client_port = unpacked_rtp_header[6]
    rtp_header_obj = RTPHeader(client_seq_num, server_ack_num, checksum, client_window_size, ack, syn, fin, nack,
                               client_ip_address_long, client_port)

    if is_debug:
        print "Unpacking Header:"
        print '\tClient Seq Num:\t' + str(client_seq_num)
        print '\tServer ACK Num:\t' + str(server_ack_num)
        print '\tChecksum:\t' + str(checksum)
        print '\tClient Window:\t' + str(client_window_size)
        print '\tACK:\t\t' + str(ack)
        print '\tSYN:\t\t' + str(syn)
        print '\tFIN:\t\t' + str(fin)
        print '\tNACK:\t\t' + str(nack)
        print '\tClient IP Long:\t' + str(client_ip_address_long)
        print '\tClient Port:\t' + str(client_port)

    return rtp_header_obj


def pack_bits(ack, syn, fin, nack):
    bit_string = str(ack) + str(syn) + str(fin) + str(nack)
    bit_string = '0000' + bit_string
    bit_string = int(bit_string, 2)

    return bit_string


def unpack_bits(bit_string):
    bit_string = format(bit_string, '08b')
    ack = int(bit_string[4])
    syn = int(bit_string[5])
    fin = int(bit_string[6])
    nack = int(bit_string[7])

    return ack, syn, fin, nack


def get(filename, conn_object, request_packet):
    try:
        file_handle = open(filename, 'rb')
    except IOError:
        print "Could not open file: {0}".format(filename)
        send(conn_object.server_seq_num, request_packet.get_header().get_seq_num() + len(request_packet.get_payload()),
             1, 0, 0, 0, 'GET|FILENOTFOUND|0')
        return
    packet_list = []  # clear out the list of packets
    while True:
        data = file_handle.read(1024)
        if not data:
            break
        packet_list.append(Packet(RTPHeader(0, 0, 0, 0, 0, 0, 0, 0, net_emu_ip_address_long, net_emu_port), data,
                                  False))
    file_handle.close()
    send(conn_object.server_seq_num, request_packet.get_header().get_seq_num() + len(request_packet.get_payload()),
         1, 0, 0, 0, 'GET|{0}|{1}'.format(filename, str(len(packet_list))))
    next_packet_to_send = 0
    num_timeouts = 0
    total_packets_sent = 0
    # repeat infinitely if need be, will be broken out of if TIMEOUT_MAX_LIMIT timeouts are reached
    while True:
        print '{0:.1f}%%'.format(total_packets_sent / len(packet_list))
        if is_debug:
            print('\t\t'),
            for i in range(0, len(packet_list) - 1):
                print(i),
            print ''
            print 'ACK''ed:\t',
            for j in range(0, len(packet_list) - 1):
                if packet_list[j].get_acknowledged():
                    print(j),
        # send (server window size) # of un-acknowledged packets in the packet list
        packets_sent_in_curr_window = 0
        for x in range(next_packet_to_send, len(packet_list) - 1):
            if not packet_list[x].get_acknowledged():  # if it has not been acknowledged
                send(conn_object.server_seq_num, 0, 0, 0, 0, 0, packet_list[x].payload)
                packets_sent_in_curr_window += 1
                if packets_sent_in_curr_window == conn_object.window_size:
                    break

        # Use temp variable to see if we actually received any
        curr_num_packets_sent = total_packets_sent

        # wait_for_acks processes all the packets received in the 5 seconds after sending the window,
        # and sets the next packet to send
        next_packet_to_send, total_packets_sent = wait_for_acks(datetime.datetime.now(), next_packet_to_send,
                                                                total_packets_sent, packet_list, conn_object)

        # if we have acknowledged all of the packets, then we are done
        if next_packet_to_send == -1:
            break
        # if we timeout then increment the number of timeouts
        if curr_num_packets_sent == next_packet_to_send:
            num_timeouts += 1
        else:
            # if we did receive reset timeouts
            num_timeouts = 0
        if num_timeouts == TIMEOUT_MAX_LIMIT:
            print 'Server Unresponsive, POST failed'
            break


def wait_for_acks(time_of_calling, next_packet_to_send, packets_sent, list_of_packets, conn_object):
    to_return_packets_sent = packets_sent

    # Look at all the windows and sequence numbers received
    client_windows_received = []
    client_seq_num_received = []

    while True:
        # Stay in the loop for 5 seconds
        if datetime.datetime.now() > time_of_calling + datetime.timedelta(seconds=5):
            break

        # Try to pull something out of the Queue, block for a second, if there is nothing there, then go to the top
        try:
            new_packet = conn_object.mailbox.get(True, 1)
        except Queue.Empty:
            continue

        # Look through the packet list to find the packet that the ACK is referencing
        for i in list_of_packets:
            if i.get_header().seq_num() + len(i.get_payload()) == new_packet.get_header().get_ack_num():
                i.acknowledged = True
                to_return_packets_sent += 1
                client_windows_received.append(new_packet.get_header().get_window())
                client_seq_num_received.append(new_packet.get_header().get_seq_num())
    conn_object.client_seq_num = max(client_seq_num_received)
    conn_object.window_size = min(client_windows_received)
    for i in range(next_packet_to_send, len(list_of_packets) - 1):
        if not list_of_packets[i].get_acknowledged():
            return i, to_return_packets_sent
    return -1, to_return_packets_sent


def check_client_list(client_ip_address, client_port):
    with client_list_lock:
        for i in range(len(clientList)):
            if clientList[i].client_ip == client_ip_address and clientList[i].client_port == client_port \
                    and clientList[i].state != State.CLOSED:
                if is_debug:
                    print 'Client found in connection list'
                return i

    if is_debug:
        print 'Client not found in connection list'
    return None


def send_synack(server_seq_num, client_ack_num, payload):
    send(server_seq_num, client_ack_num, 1, 1, 0, 0, payload)


def send_nack(server_seq_num, client_ack_num):
    send(server_seq_num, client_ack_num, 0, 0, 0, 1, EMPTY_PAYLOAD)


def send_ack(server_seq_num, client_ack_num):
    send(server_seq_num, client_ack_num, 1, 0, 0, 0, EMPTY_PAYLOAD)


def send_fin(server_seq_num, client_ack_num):
    send(server_seq_num, client_ack_num, 0, 0, 1, 0, EMPTY_PAYLOAD)


def complete_client_disconnect(client_loc, num_timeouts):
    # Change sequence and acknowledge numbers to correct ones before sending to server
    clientList[client_loc].server_seq_num += 1
    clientList[client_loc].calc_client_server_send_seq_ack_nums(EMPTY_PAYLOAD)

    # Send out the FIN packet to end connection
    send_fin(clientList[client_loc].server_seq_num, clientList[client_loc].client_ack_num)
    clientList[client_loc].state = State.LAST_ACK
    packet = None

    try:
        packet = clientList[client_loc].mailbox.get(False)
    except Queue.Empty:
        if num_timeouts == TIMEOUT_MAX_LIMIT:
            print "rabithole1" * 5
            return False
        else:
            # If we have timed out less than TIMEOUT_MAX_LIMIT times, then try again with num_timeouts incremented
            print('.'),
            clientList[client_loc].client_state = State.CLOSE_WAIT
            print "rabithole2" * 5
            return complete_client_disconnect(client_loc, num_timeouts + 1)

    rtp_header = packet.get_header()
    payload = packet.get_payload()

    # Increment and save counters
    client_seq_num_temp = clientList[client_loc].client_seq_num
    server_ack_num_temp = clientList[client_loc].server_ack_num
    clientList[client_loc].calc_client_server_recv_seq_ack_nums(rtp_header, payload)

    # if rtp_header.get_ack_num() != clientList[client_loc].client_seq_num:
    #     clientList[client_loc].client_seq_num = client_seq_num_temp
    #     clientList[client_loc].server_ack_num = server_ack_num_temp
    #     clientList[client_loc].state = State.CLOSE_WAIT
    #     clientList[client_loc].server_seq_num -= 1
    #     print "rabithole3"*5
    #     return complete_client_disconnect(client_loc, num_timeouts + 1)

    if rtp_header.get_ack():
        clientList[client_loc].state = State.CLOSED
        print "Client has disconnected"
        return True


class Connection:
    def __init__(self, seq_num, window_size, ack, syn, fin, nack, client_ip, client_port):
        self.state = State.LISTEN
        self.client_seq_num = seq_num
        self.client_ack_num = self.client_seq_num
        self.server_seq_num = 100  # random.randint(0, 2**32-1) TODO - reset to random once most of the testing is complete
        self.server_ack_num = self.server_seq_num
        self.client_seq_num_last_state = self.client_seq_num
        self.client_ack_num_last_state = self.client_ack_num
        self.server_seq_num_last_state = self.server_seq_num
        self.server_ack_num_last_state = self.server_ack_num
        self.window_size = window_size
        self.last_ack = ack
        self.last_syn = syn
        self.last_fin = fin
        self.last_nack = nack
        self.client_ip = client_ip
        self.client_port = client_port
        self.timer = ''  # threading.Timer(10, dummy())
        # self.timer.start()
        self.hash = hashlib.sha224(str(random.randint(0, 2 ** 64 - 1))).hexdigest()
        self.hash_of_hash = hashlib.sha224(self.hash).hexdigest()
        self.hash_from_client = ''
        self.payload = ''
        self.mailbox = Queue.Queue(maxsize=QUEUE_MAX_SIZE)

    def is_client_setup(self):
        # if client is not in either of these states; client is setup
        if self.state != State.SYN_RECEIVED and self.state != State.SYN_SENT_HASH and self.state != State.LISTEN:
            return True
        return False

    def in_disconnect_state(self):
        if self.state == State.CLOSE_WAIT or self.state == State.LAST_ACK:
            return True
        return False


    # def reverse_state(self):
    #     self.server_seq_num = self.server_seq_num_last_state
    #     self.server_ack_num = self.server_ack_num_last_state
    #     self.client_seq_num = self.client_seq_num_last_state
    #     self.client_ack_num = self.client_ack_num_last_state

    def calc_client_server_send_seq_ack_nums(self, payload):

        # self.server_ack_num_last_state = self.server_ack_num
        # self.client_seq_num_last_state = self.client_seq_num

        if len(payload) == 0:
            self.server_ack_num = self.server_seq_num + 1
        else:
            self.server_ack_num = self.server_seq_num + len(payload)

        # self.client_seq_num = self.client_ack_num

    def calc_client_server_recv_seq_ack_nums(self, payload):

        # self.server_seq_num_last_state = self.server_seq_num
        # self.client_ack_num_last_state = self.client_ack_num

        self.server_seq_num = self.server_ack_num

        if len(payload) == 0:
            self.client_ack_num = self.client_seq_num + 1
        else:
            self.client_ack_num = self.client_seq_num + len(payload)

    # def timeout(self, go_back_state):
    #     self.state = go_back_state
    #     print "timeout works; please delete me when done testing"
    #     # Todo - go back to original seq and ack nums

    # def increase_seq_num(self, amount):
    #     self.seq_num += amount

    # def timeout(self):
    #     if self.state == State.SYN_RECEIVED:
    #         self.state = State.LISTEN
    #         self.update_on_receive()



    def update_on_receive(self, ack, syn, fin, nack, client_loc):

        #print self.state
        # Todo - need to reset state back to seq and ack numbers at established state


        if self.state == State.ESTABLISHED:
            if syn and ack:
                self.state = State.SYN_RECEIVED
            elif not syn and not ack and fin:
                self.state = State.CLOSE_WAIT
                self.calc_client_server_send_seq_ack_nums(EMPTY_PAYLOAD)
                send_ack(self.server_seq_num, self.client_ack_num)

        if self.state == State.CLOSE_WAIT:
            # self.state = State.LAST_ACK

            # client_loc = check_client_list(self.client_ip, self.client_port)
            complete_client_disconnect(client_loc, 0)
            # disconnect_t = threading.Thread(target=complete_client_disconnect, args=(client_loc, 0))
            # disconnect_t.daemon = True
            # disconnect_t.start()
            # disconnect_t.join()

            # self.calc_client_server_send_seq_ack_nums(EMPTY_PAYLOAD)
            # self.timer = threading.Timer(TIMEOUT_TIME, self.timeout(State.CLOSE_WAIT))
            # send_fin(self.server_seq_num, self.client_ack_num)

        # if self.state == State.LAST_ACK:
        #     self.timer.cancel()
        #     if not syn and ack and not fin:
        #         self.state = State.CLOSED
        #     else:
        #         self.state = State.CLOSE_WAIT

        if self.state == State.SYN_RECEIVED:
            if syn and not ack:
                self.state = State.LISTEN
            elif syn and ack:
                # Hashes match; complete 4-way handshake
                if self.hash_from_client == self.hash_of_hash:
                    self.state = State.ESTABLISHED
                    # self.calc_server_seq_ack_nums(EMPTY_PAYLOAD)
                    self.calc_client_server_send_seq_ack_nums(EMPTY_PAYLOAD)
                    # print "SYN_RECV"
                    send_ack(self.server_seq_num, self.client_ack_num)
                # Hashes don't match; send nack
                else:
                    send_nack(self.server_seq_num, self.client_ack_num)

        if self.state == State.LISTEN:
            if syn and not ack:
                self.state = State.SYN_RECEIVED
                # self.calc_server_seq_ack_nums(self.hash)
                self.calc_client_server_send_seq_ack_nums(self.hash)
                # print "LISTEN"
                send_synack(self.server_seq_num, self.client_ack_num, self.hash)

        # TODO 3 MINUTES

        # Todo - shutdown server and send disconnect command to all clients

        # elif self.state == State.ESTABLISHED:
        #    if nack:
        #         pass
        #    if not syn and not ack and fin:
        #         self.state = State.CLOSE_WAIT
        #         ack()
        # elif self.state == State.LAST_ACK:
        #     if not syn and ack and not fin:
        #         self.state = State.CLOSED
        # elif self.state == State.FIN_WAIT_1:
        #     if not syn and not ack and fin:
        #         ack()
        #         self.state = State.CLOSING
        #     if not syn and ack and not fin:
        #         self.state = State.FIN_WAIT_2
        #     if not syn and ack and fin:
        #         ack()
        #         self.state = State.TIME_WAIT
        # elif self.state == State.FIN_WAIT_2:
        #     if not syn and not ack and fin:
        #         ack()
        #         self.state = State.TIME_WAIT
        # elif self.state == State.CLOSING:
        #     if not syn and ack and not fin:
        #         self.state = State.TIME_WAIT
        # else:
        #    print('state not valid')

        if self.state == State.ESTABLISHED:
            client_ip_address = socket.inet_ntoa(struct.pack("!L", self.client_ip))
            print "Client %s %s supposedly established or re-established." % (client_ip_address, self.client_port)

        if self.state == State.CLOSED:
            client_ip_address = socket.inet_ntoa(struct.pack("!L", self.client_ip))
            print "Client %s %s has been disconnected." % (client_ip_address, self.client_port)


class State:
    LISTEN = 0
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
    def __init__(self, header, payload, acknowledged):
        self.header = header
        self.payload = payload
        self.acknowledged = acknowledged

    def get_header(self):
        return self.header

    def get_payload(self):
        return self.payload

    def get_acknowledged(self):
        return self.acknowledged


if __name__ == "__main__":
    # Misc Global variables
    BUFFER_SIZE = 1045  # 21 bytes for rtp_header and 1024 bytes for payload
    is_debug = False
    terminate = False
    EMPTY_PAYLOAD = ''
    TIMEOUT_MAX_LIMIT = 25
    TIMEOUT_TIME = 1
    TIME_MAX = 60 # 1 minute
    QUEUE_MAX_SIZE = 10

    # Server
    server_window_size = 1
    server_port = ''
    SERVER_IP_ADDRESS = socket.gethostbyname(socket.gethostname())
    SERVER_IP_ADDRESS_LONG = struct.unpack("!L", socket.inet_aton(SERVER_IP_ADDRESS))[0]
    # server_seq_num = 0  # random.randint(0, 2**32-1)
    # server_ack_num = server_seq_num
    process_queue = Queue.Queue(maxsize=QUEUE_MAX_SIZE)

    # NetEmu
    net_emu_ip_address = ''
    net_emu_ip_address_long = ''
    net_emu_port = ''
    net_emu_addr = ''

    # Client
    clientList = []
    client_list_lock = threading.Lock()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        print 'Failed to create socket'
        sys.exit()

    main(sys.argv[1:])
