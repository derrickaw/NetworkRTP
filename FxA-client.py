import Queue
import datetime
import hashlib
import os
import random
import re
import socket
import struct
import sys
import threading
import time


def main(argv):
    global client_port
    global net_emu_ip_address
    global net_emu_port
    global net_emu_addr
    global client_window_size
    global client_seq_num
    global is_debug
    global is_connected
    global is_disconnected

    # Check for correct number of parameters
    if len(argv) < 3 or len(argv) > 4:
        print("Correct usage: FxA-Client X A P [-debug]")
        sys.exit(1)

    client_port = argv[0]
    net_emu_ip_address = argv[1]
    net_emu_port = argv[2]
    is_debug_arg = ''
    if len(argv) == 4:
        is_debug_arg = argv[3]
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

    # Check for debug
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

    t_connect = ''

    # Setup for Client Command Instructions
    print "*"*80
    print('Command Options:')
    print('connect\t\t|\tConnects to the FxA-server')
    print('get F\t\t|\tRetrieve file F from FxA-server')
    print('post F\t\t|\tPushes file F to the FxA-server')
    print("window W\t|\tSets the maximum receiver's window size")
    print("disconnect\t|\tDisconnect from the FxA-server")
    print "*"*80
    print

    while not is_disconnected:  # command_input != 'disconnect':
        command_input = raw_input('Please enter command: ')
        if command_input == 'connect':
            if not is_connected:
                # start connect
                try:
                    t_connect = threading.Thread(target=connect, args=(State.SYN_SENT, 0))
                    t_connect.daemon = True
                    t_connect.start()
                    print "Establishing connection..."
                    time.sleep(3) # Allow connection to establish before printing a new command line; more for format
                except:
                    "error\n"
            else:
                print ("Client already connected to server\n")
        elif command_input == 'disconnect':
            if is_connected:
                try:
                    t_disconnect = threading.Thread(target=disconnect, args=(State.ESTABLISHED, 0))
                    t_disconnect.daemon = True
                    t_disconnect.start()
                    t_disconnect.join() # Stay here until disconnect is complete
                except:
                    "Error\n"
            else:
                print "There must be a connection with the server to disconnect.  Try connecting first."
        else:
            command_input_split = command_input.split(" ")
            if command_input_split[0] == 'get':
                if len(command_input_split) != 2:
                    print("Invalid command: get requires secondary parameter\n")
                    continue
                if is_connected:
                    # Todo - check for input
                    get(command_input_split[1])
                else:
                    print('get not valid without existing connection\n')
            elif command_input_split[0] == 'post':
                if len(command_input_split) != 2:
                    # Todo - check for input
                    print("Invalid command: post requires secondary parameter\n")
                    continue
                if is_connected:
                    post(command_input_split[1])
                else:
                    print('post not valid without existing connection\n')
            elif command_input_split[0] == 'window':
                if len(command_input_split) != 2:
                    print("Invalid command: window requires secondary parameter\n")
                    continue
                try:
                    window_size = int(command_input_split[1])
                except ValueError:
                    print('Invalid window size (not a number): %s' % command_input_split[1])
                    continue
                if window_size < 1 or window_size > 2**32 - 1:
                    print("Invalid window size; must be between 1-4294967295, inclusive\n")
                    continue
                # TODO window()
                print('window')
            else:
                print("Command not recognized\n")


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

            # client_seq_num, client_ack_num, checksum, client_window_size, ack, syn, fin, nack, client_ip_address_long, \
            #     client_port = unpack_rtpheader(rtp_header)

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


def connect(client_state_temp, num_timeouts):
    global client_state_master
    global server_hash_challenge
    global is_connected
    global client_timer

    while True:
        # Check if timeouts have reached the max limit; if so, return False
        if num_timeouts > TIMEOUT_MAX_LIMIT:
            client_timer.cancel()
            print "Connection process timed-out, try again later\n"
            is_connected = False
            break

        if client_state_temp == State.RCV:
            rtp_header, payload = recv()
            client_timer.cancel()
            #calc_server_ack_num(rtp_header, payload) # Increment server seq and ack nums

            # Check checksum; if bad, drop packet, don't send nack, and go back to Master State
            if not check_checksum(rtp_header.get_checksum(), rtp_header, payload):
                client_timer = threading.Timer(TIMEOUT_TIME, connect_timeout, args=(num_timeouts,))
                client_timer.start()
                client_state_temp = client_state_master

                if is_debug:
                    print "Checksum checker detected error on challenge from server, sending nothing"


            # Check for duplicate packet
            elif rtp_header.get_ack_num() == client_seq_num:
                client_state_temp = client_state_master

            else:
                calc_client_server_recv_seq_ack_nums(rtp_header, payload)

                # Check if correct seq and ack nums were sent
                if not check_packet_seq_ack_nums(rtp_header, payload):
                    client_state_temp = client_state_master
                    print "Not correct ack"

                # If nack recv, send temp state to master state seen last
                elif rtp_header.get_nack():
                    client_state_temp = client_state_master

                # If syn and ack, then master and temp states change to SYN_SENT_HASH
                elif rtp_header.get_syn() and rtp_header.get_ack():
                    server_hash_challenge = payload
                    client_state_temp = State.SYN_SENT_HASH
                    client_state_master = State.SYN_SENT_HASH

                # If not syn and ack, then master and temp states change to ESTABLISHED
                elif not rtp_header.get_syn() and rtp_header.get_ack():
                    # client_state_temp = State.ESTABLISHED
                    client_state_master = State.ESTABLISHED
                    if is_debug:
                        print "Received ACK from server, connection established"
                    print "Connection with server has been established."
                    is_connected = True
                    break

        # Send request to connect
        if client_state_temp == State.SYN_SENT:
            client_timer = threading.Timer(TIMEOUT_TIME, connect_timeout, args=(num_timeouts,))
            client_timer.start()
            client_state_temp = State.RCV

            if is_debug:
                print "Sending initial SYN to server"
            send_syn()

        # Send hash_of_hash to finalize 4-way handshake
        if client_state_temp == State.SYN_SENT_HASH:
            client_timer = threading.Timer(TIMEOUT_TIME, connect_timeout, args=(num_timeouts,))
            client_timer.start()
            client_state_temp = State.RCV

            if is_debug:
                print "Sending SYN + ACK + response"
            send_synack(server_hash_challenge)


def disconnect(client_state_temp, num_timeouts):

    global client_state_master
    global client_timer
    global is_disconnected

    while True:
        # Check if timeouts have reached the max limit; if so, return back to Established state
        if num_timeouts > TIMEOUT_MAX_LIMIT:
            client_timer.cancel()
            print "Connection process timed-out, try again later; re-establishing full connection with server\n"
            client_state_master = State.ESTABLISHED
            break

        if client_state_temp == State.RCV:
            rtp_header, payload = recv()
            client_timer.cancel()

            # Check checksum; if bad, drop packet, don't send nack, and go back to Master State
            if not check_checksum(rtp_header.get_checksum(), rtp_header, payload):
                client_timer = threading.Timer(TIMEOUT_TIME, disconnect_timeout, args=(num_timeouts,))
                client_timer.start()
                client_state_temp = client_state_master

                if is_debug:
                    print "Checksum checker detected error on challenge from server, sending nothing"

            # Check for duplicate packet
            elif rtp_header.get_ack_num() == client_seq_num:
                client_state_temp = client_state_master

            else:
                calc_client_server_recv_seq_ack_nums(rtp_header, payload)

            # Check if correct seq and ack nums were sent
            if not check_packet_seq_ack_nums(rtp_header, payload):
                client_state_temp = client_state_master
                print "Not correct ack"

            # If nack recv, send temp state to master state seen last
            elif rtp_header.get_nack():
                client_state_temp = client_state_master

            # If FIN + ACK, then master and temp states change to TIME_WAIT
            elif rtp_header.get_ack() and rtp_header.get_fin():
                client_state_temp = State.TIME_WAIT
                client_state_master = State.TIME_WAIT

            # If ACK and current state is CLOSING, then master and temp states change to TIME_WAIT
            elif rtp_header.get_ack() and not rtp_header.get_fin() and client_state_master == State.CLOSING:
                client_state_temp = State.TIME_WAIT
                client_state_master = State.TIME_WAIT

            # If FIN and current state is FIN_WAIT_2, then master and temp states change to TIME_WAIT
            elif not rtp_header.get_ack() and rtp_header.get_fin() and client_state_master == State.FIN_WAIT_2:
                client_state_temp = State.TIME_WAIT
                client_state_master = State.TIME_WAIT

            # If ACK and current state is FIN_WAIT_1, then master and temp states change to FIN_WAIT_2
            elif rtp_header.get_ack() and not rtp_header.get_fin() and client_state_master == State.FIN_WAIT_1:
                client_state_temp = State.FIN_WAIT_2
                client_state_master = State.FIN_WAIT_2

            # If FIN and current state is FIN_WAIT_1, then master and temp states change to CLOSING
            elif not rtp_header.get_ack() and rtp_header.get_fin() and client_state_master == State.FIN_WAIT_1:
                client_state_temp = State.CLOSING
                client_state_master = State.CLOSING

        # Send initial request to disconnect
        if client_state_temp == State.ESTABLISHED:
            client_timer = threading.Timer(TIMEOUT_TIME, disconnect_timeout, args=(num_timeouts,))
            client_timer.start()
            client_state_master = State.FIN_WAIT_1
            client_state_temp = State.RCV

            if is_debug:
                print "Sending initial FIN to server"
            send_fin()

        # Moving to either TIME_OUT or CLOSING state
        if client_state_temp == State.FIN_WAIT_1:
            client_timer = threading.Timer(TIMEOUT_TIME, disconnect_timeout, args=(num_timeouts,))
            client_timer.start()
            client_state_temp = State.RCV

            if is_debug:
                print "Sending ACK to server to move to TIME_OUT or CLOSING state"
            send_ack()

        # Moving to TIME_OUT state
        if client_state_temp == State.FIN_WAIT_2:
            client_timer = threading.Timer(TIMEOUT_TIME, disconnect_timeout, args=(num_timeouts,))
            client_timer.start()
            client_state_temp = State.RCV

            if is_debug:
                print "Sending ACK to server to move to TIME_OUT state"
            send_ack()

        # Waiting for ACK from server
        if client_state_temp == State.CLOSING:
            client_timer = threading.Timer(TIMEOUT_TIME, disconnect_timeout, args=(num_timeouts,))
            client_timer.start()
            client_state_temp = State.RCV

            if is_debug:
                print "Waiting for ACK from server to move to TIME_OUT state"

        # Moving to CLOSED state
        if client_state_temp == State.TIME_WAIT:
            client_state_master = State.CLOSED
            if is_debug:
                print "Connection is closed with server."
            is_disconnected = True
            break


def disconnect_timeout(num_timeouts):

    if client_state_master == State.SYN_SENT:
        client_state_temp = State.SYN_SENT
        num_timeouts += 1
        connect(client_state_temp, num_timeouts)
    elif client_state_master == State.SYN_SENT_HASH:
        client_state_temp = State.SYN_SENT_HASH
        num_timeouts += 1
        connect(client_state_temp, num_timeouts)


def check_packet_seq_ack_nums(rtp_header, payload):

    # First compare calculated server_seq_nums to recv server_seq_num
    server_seq_num_correct = False
    if server_seq_num == rtp_header.get_seq_num():
        server_seq_num_correct = True

    # Second check client ack number matches seq number
    client_ack_num_correct = False
    if client_ack_num == rtp_header.get_ack_num():
        client_ack_num_correct = True

    return server_seq_num_correct and client_ack_num_correct


def calc_client_server_send_seq_ack_nums(payload):
    global client_ack_num
    global server_seq_num

    if len(payload) == 0:
        client_ack_num = client_seq_num + 1
    else:
        client_ack_num = client_seq_num + len(payload)

    server_seq_num = server_ack_num


def calc_client_server_recv_seq_ack_nums(rtp_header, payload):
    global client_seq_num
    global server_ack_num
    global server_seq_num

    if server_seq_num == 0:
        server_seq_num = rtp_header.get_seq_num()

    client_seq_num = client_ack_num

    if len(payload) == 0:
        server_ack_num = server_seq_num + 1
    else:
        server_ack_num = server_seq_num + len(payload)


def calc_server_ack_num(rtp_header, payload):
    global server_seq_num
    global server_ack_num

    print server_seq_num
    print server_ack_num
    # Compute what the server seq and ack numbers should be based on the payload
    if server_seq_num == 0:
        server_seq_num = rtp_header.get_seq_num()
    else:
        server_seq_num = server_ack_num
    if len(payload) == 0:
        server_ack_num = server_seq_num + 1
    else:
        server_ack_num = server_seq_num + len(payload)
    print server_seq_num
    print server_ack_num


def connect_timeout(num_timeouts):

    if client_state_master == State.SYN_SENT:
        client_state_temp = State.SYN_SENT
        num_timeouts += 1
        connect(client_state_temp, num_timeouts)
    elif client_state_master == State.SYN_SENT_HASH:
        client_state_temp = State.SYN_SENT_HASH
        num_timeouts += 1
        connect(client_state_temp, num_timeouts)


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
            packet.get_header().get_ack_num() == client_seq_num + len(payload) + 1 and \
            packet.get_header().get_ack() and not packet.get_header().get_nack:
        return True
    else:
        print('.'),
        send_and_wait_for_ack(payload, 0)


def post(filename):
    global total_packets_sent
    global packet_list

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
    else:
        while True:
            data = file_handle.read(1024)
            if not data:
                break
            packet_list.append(Packet(RTPHeader(0, 0, 0, 0, 0, 0, 0, 0, net_emu_ip_address_long, net_emu_port), data,
                                      False))
        next_packet_to_send = 0
        num_timeouts = 0
        total_packets_sent = 0
        # repeat infinitely if need be, will be broken out of if TIMEOUT_MAX_LIMIT timeouts are reached
        while True:
            print '{0:.1f}%%'.format(total_packets_sent/len(packet_list))
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
                    send(0, 0, 0, 0, packet_list[x].payload)
                    packets_sent_in_curr_window += 1
                    if packets_sent_in_curr_window == server_window_size:
                        break
            # wait_for_acks processes all the packets received in the 5 seconds after sending the window,
            # and sets the next packet to send
            new_next_packet_to_send = wait_for_acks(datetime.datetime.now(), next_packet_to_send)
            # if we have acknowledged all of the packets, then we are done
            if next_packet_to_send == -1:
                break
            # if we timeout then increment the number of timeouts
            if new_next_packet_to_send == next_packet_to_send:
                num_timeouts += 1
            else:
                # if we did receive reset timeouts
                num_timeouts = 0
            if num_timeouts == TIMEOUT_MAX_LIMIT:
                print 'Server Unresponsive, POST failed'
                break


def wait_for_acks(time_of_calling, next_packet_to_send):
    global server_window_size
    global server_seq_num
    global total_packets_sent
    global packet_list

    server_windows_received = []
    server_seq_num_received = []
    while True:
        if datetime.datetime.now() > time_of_calling + datetime.timedelta(seconds=5):
            break
        new_packet = process_queue.get(True, 1)
        seq_num = new_packet.get_header().get_ack_num() - 1025
        for i in packet_list:
            if i.get_header().seq_num() == seq_num:
                i.acknowledged = True
                total_packets_sent += 1
                server_windows_received.append(i.get_header().get_window())
                server_seq_num_received.append(i.get_header().get_seq_num())
    server_seq_num = max(server_seq_num_received)
    server_window_size = min(server_windows_received)
    for i in range(next_packet_to_send, len(packet_list) - 1):
        if not packet_list[i].get_acknowledged():
            return i
    return -1


def send(ack, syn, fin, nack, payload):

    # Change sequence and acknowledge numbers to correct ones before sending to server
    #calc_client_seq_ack_nums(payload)
    calc_client_server_send_seq_ack_nums(payload)

    # Calculate checksum on rtp_header and payload with a blank checksum
    checksum = 0
    rtp_header_obj = RTPHeader(client_seq_num, server_ack_num, checksum, client_window_size, ack, syn, fin, nack,
                               CLIENT_IP_ADDRESS_LONG, client_port)
    packed_rtp_header = pack_rtpheader(rtp_header_obj)
    packet = packed_rtp_header + payload
    checksum = sum(bytearray(packet))

    # Install checksum into rtp_header and package up with payload
    rtp_header_obj = RTPHeader(client_seq_num, server_ack_num, checksum, client_window_size, ack, syn, fin, nack,
                               CLIENT_IP_ADDRESS_LONG, client_port)
    packed_rtp_header = pack_rtpheader(rtp_header_obj)
    packet = packed_rtp_header + payload

    if is_debug:
        print "Sending:"
        print '\tClient Seq Num:\t' + str(client_seq_num)
        print '\tServer ACK Num:\t' + str(server_ack_num)
        print '\tChecksum:\t' + str(checksum)
        print '\tClient Window:\t' + str(client_window_size)
        print '\tACK:\t\t' + str(ack)
        print '\tSYN:\t\t' + str(syn)
        print '\tFIN:\t\t' + str(fin)
        print '\tNACK:\t\t' + str(nack)
        print '\tClient IP Long:\t' + str(CLIENT_IP_ADDRESS_LONG)
        print '\tClient Port:\t' + str(client_port)
        print '\tPayload:\t' + str(payload)
        print '\tSze-Pyld:\t' + str(len(payload))

    sock.sendto(packet, net_emu_addr)


def recv():

    recv_packet = sock.recvfrom(BUFFER_SIZE)
    packet = recv_packet[0]
    rtp_header = packet[0:21]
    payload = packet[21:]
    rtp_header = unpack_rtpheader(rtp_header, payload)

    if is_debug:
        print 'Received Payload (may be corrupted):'
        print str(payload)

    return rtp_header, payload


def pack_rtpheader(rtp_header):

    flags = pack_bits(rtp_header.get_ack(), rtp_header.get_syn(), rtp_header.get_fin(), rtp_header.get_nack())
    rtp_header = struct.pack('!LLHLBLH', rtp_header.get_seq_num(), rtp_header.get_ack_num(), rtp_header.get_checksum(),
                             rtp_header.get_window(), flags, rtp_header.get_ip(), rtp_header.get_port())

    return rtp_header


def unpack_rtpheader(packed_rtp_header, payload):
    global server_window_size
    #global server_seq_num
    #global server_ack_num
    global server_port

    unpacked_rtp_header = struct.unpack('!LLHLBLH', packed_rtp_header)  # 21 bytes
    server_seq_num_local = unpacked_rtp_header[0]
    client_ack_num_test = unpacked_rtp_header[1]
    checksum = unpacked_rtp_header[2]
    server_window_size = unpacked_rtp_header[3]
    flags = unpacked_rtp_header[4]
    ack, syn, fin, nack = unpack_bits(flags)
    server_ip_address_long = unpacked_rtp_header[5]
    server_port = unpacked_rtp_header[6]
    rtp_header_obj = RTPHeader(server_seq_num_local, client_ack_num_test, checksum, server_window_size, ack, syn, fin, nack,
                               server_ip_address_long, server_port)

    if is_debug:
        print "Unpacking Header:"
        print '\tServer Seq Num:\t' + str(server_seq_num_local)
        print '\tClient ACK Num:\t' + str(client_ack_num_test)
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


def create_hash(hash_challenge):
    hash_of_hash = hashlib.sha224(hash_challenge).hexdigest()
    return hash_of_hash


def send_syn():

    send(0, 1, 0, 0, CLIENT_EMPTY_PAYLOAD)


def send_synack(payload):

    if payload != CLIENT_EMPTY_PAYLOAD:
        payload = create_hash(payload)

    send(1, 1, 0, 0, payload)


def send_ack():
    send(1, 0, 0, 0, CLIENT_EMPTY_PAYLOAD)

def send_nack():
    send(0, 0, 0, 1, CLIENT_EMPTY_PAYLOAD)

def send_fin():
    send(0, 0, 1, 0, CLIENT_EMPTY_PAYLOAD)

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
    CLOSED = 12

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

    # Client
    client_window_size = 1
    client_port = ''
    CLIENT_IP_ADDRESS = socket.gethostbyname(socket.gethostname())
    CLIENT_IP_ADDRESS_LONG = struct.unpack("!L", socket.inet_aton(CLIENT_IP_ADDRESS))[0]
    #print CLIENT_IP_ADDRESS_LONG
    #print CLIENT_IP_ADDRESS
    client_seq_num = 0  # random.randint(0, 2**32-1)  # Todo - fix when done testing, Should we also consider wrap around?
    client_ack_num = client_seq_num
    client_timer = ''
    CLIENT_EMPTY_PAYLOAD = ''
    TIMEOUT_MAX_LIMIT = 25
    TIMEOUT_TIME = 1
    client_state_master = State.SYN_SENT
    packet_list = []
    is_connected = False
    is_disconnected = False
    total_packets_sent = 0

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
