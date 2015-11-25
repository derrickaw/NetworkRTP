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
    global fin_terminate
    global fin_listen_termination_lock

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

    # start packet collection
    try:
        recv_t = threading.Thread(target=recv_packet, args=())
        recv_t.daemon = True
        recv_t.start()
    except RuntimeError:
        print "Error creating/starting client slave thread(s)"

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

    fin_listener = threading.Thread(target=listen_for_fin)
    fin_listener.daemon = True

    while command_input != 'disconnect':
        command_input = raw_input('Please enter command: ')
        if is_connected:
            fin_listener.start()
        if command_input == 'connect':
            if not is_connected:
                # start connect
                try:
                    connect_t = threading.Thread(target=connect, args=(0,))
                    connect_t.daemon = True
                    connect_t.start()
                    print "Establishing connection..."
                except RuntimeError:
                    "Error creating/starting client connect thread"
            else:
                print ("Client already connected to server\n")
        elif command_input == 'disconnect':
            if is_connected:
                with fin_listen_termination_lock:
                    fin_terminate = True
                fin_listener.join()
                try:
                    disconnect_t = threading.Thread(target=disconnect, args=(0,))
                    disconnect_t.daemon = True
                    disconnect_t.start()
                    print "Trying to disconnect..."
                    disconnect_t.join()
                except RuntimeError:
                    "Error creating/starting client disconnect thread"
            else:
                command_input = "None" # Reset to keep the while loop going
                print "There must be a connection with the server to disconnect.  Try connecting first."
        else:
            command_input_split = command_input.split(" ")
            if command_input_split[0] == 'get':
                if len(command_input_split) != 2:
                    print("Invalid command: get requires secondary parameter\n")
                    continue
                if is_connected:
                    # TODO - check for input
                    with fin_listen_termination_lock:
                        fin_terminate = True
                    fin_listener.join()
                    try:
                        # startup get thread
                        get_t = threading.Thread(target=get, args=(command_input_split[1],))
                        get_t.daemon = False
                        get_t.start()
                        get_t.join()  # TODO - block for now, allow multiple calls later
                    except RuntimeError:
                        "Error getting file on get thread"
                else:
                    print('get not valid without existing connection\n')
            elif command_input_split[0] == 'post':
                if len(command_input_split) != 2:
                    print("Invalid command: post requires secondary parameter\n")
                    continue
                if is_connected:
                    # TODO - check for input
                    with fin_listen_termination_lock:
                        fin_terminate = True
                    fin_listener.join()
                    try:
                        # startup post thread
                        post_t = threading.Thread(target=post, args=(command_input_split[1],))
                        post_t.daemon = False
                        post_t.start()
                        post_t.join()  # TODO - block for now, allow multiple calls later
                    except:
                        "Error on posting file on post thread"
                else:
                    print('post not valid without existing connection\n')
            elif command_input_split[0] == 'window':
                if len(command_input_split) != 2:
                    print("Invalid command: window requires secondary parameter\n")
                    continue
                try:
                    window_size = int(command_input_split[1])
                    print('Client Receiving Window = %s' % command_input_split[1])
                except ValueError:
                    print('Invalid window size (not a number): %s' % command_input_split[1])
                    continue
                if window_size < 1 or window_size > 2**32 - 1:
                    print("Invalid window size; must be between 1-4294967295, inclusive\n")
                    continue
            else:
                print("Command not recognized\n")


def listen_for_fin():
    while True:
        try:
            packet = process_queue.get(False)
        except Queue.Empty:
            with fin_listen_termination_lock:
                if fin_terminate:
                    return
            continue
        if packet.get_header().get_fin() == 1:
            print 'Received termination from server, now disconnecting'
            disconnect() # TODO
        else:
            # Why the hell do I have this packet in the first place? Put it back in the Queue and hope the owner sees it
            process_queue.put(packet, True, TIMEOUT_TIME)
            return


def recv_packet():
    global server_window_size

    while True:
        try:
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

                # Update server window size
                server_window_size = rtp_header.get_window()

                # Enqueue packet to main MAILBOX queue
                processed_packet = Packet(rtp_header, payload, 0)
                process_queue.put(processed_packet)

        except socket.error, msg:
            continue


def connect(num_timeouts):

    global is_connected

    challenge_packet, num_timeouts_updated = obtain_challenge_packet(num_timeouts)

    if challenge_packet is None or not complete_challenge(challenge_packet, num_timeouts_updated):
        is_connected = False
        if is_debug:
            print "Didn't receive final ACK from server, connection not established"
        print "Connection was refused...try again later."
    else:
        is_connected = True

        if is_debug:
            print "Received ACK from server, connection established"
        print "Connection with server has been established."


def obtain_challenge_packet(num_timeouts):
    global client_state_master
    global client_seq_num
    global server_ack_num

    # Change sequence and acknowledge numbers to correct ones before sending to server
    calc_client_server_send_seq_ack_nums(EMPTY_PAYLOAD)

    # Send out the SYN packet to start connection
    send_syn(client_seq_num, server_ack_num)
    packet = None
    try:
        # Wait until the process queue has a packet, block for TIMEOUT_TIME seconds
        packet = process_queue.get(True, TIMEOUT_TIME)
    except Queue.Empty:  # If after blocking there still was not a packet in the queue
        # If we have timed out TIMEOUT_MAX_LIMIT times, then cancel the operation
        if num_timeouts == TIMEOUT_MAX_LIMIT:
            return None, None
        else:
            # If we have timed out less than TIMEOUT_MAX_LIMIT times, then try again with num_timeouts incremented
            print('.'),
            return obtain_challenge_packet(num_timeouts + 1)

    rtp_header = packet.get_header()
    payload = packet.get_payload()

    # Increment and save counters
    client_seq_num_temp = client_seq_num
    # server_ack_num_temp = server_ack_num
    calc_client_server_recv_seq_ack_nums(rtp_header, payload)

    if rtp_header.get_ack_num() != client_ack_num:
        client_seq_num = client_seq_num_temp
        # server_ack_num = server_ack_num_temp
        return obtain_challenge_packet(num_timeouts + 1)

    else:
        client_state_master = State.SYN_SENT_HASH
        return packet, num_timeouts


def complete_challenge(challenge_packet, num_timeouts):

    global client_state_master
    global client_seq_num
    global server_ack_num

    # Change sequence and acknowledge numbers to correct ones before sending to server
    calc_client_server_send_seq_ack_nums(challenge_packet.get_payload())

    # Send out the SYN+ACK+HASH packet to complete final handshake part
    send_synack(challenge_packet.get_payload(), client_seq_num, server_ack_num)
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
            return complete_challenge(challenge_packet, num_timeouts + 1)

    rtp_header = packet.get_header()
    payload = packet.get_payload()

    # Increment and save counters
    client_seq_num_temp = client_seq_num
    server_ack_num_temp = server_ack_num
    calc_client_server_recv_seq_ack_nums(rtp_header, payload)

    if rtp_header.get_ack_num() != client_seq_num:
        client_seq_num = client_seq_num_temp
        server_ack_num = server_ack_num_temp
        return complete_challenge(challenge_packet, num_timeouts + 1)
    else:
        client_state_master = State.ESTABLISHED
        return True


def disconnect(num_timeouts):

    global is_disconnected

    first_part_complete, num_timeouts_updated = begin_disconnect(num_timeouts)

    if first_part_complete and end_disconnect(num_timeouts_updated):
        print "disconnect true"
        is_disconnected = True


def begin_disconnect(num_timeouts):

    global client_state_master
    global client_seq_num
    global server_ack_num

    # Change sequence and acknowledge numbers to correct ones before sending to server
    calc_client_server_send_seq_ack_nums(EMPTY_PAYLOAD)

    # Send out the SYN+ACK+HASH packet to complete final handshake part
    send_fin(client_seq_num, server_ack_num)
    try:
        # Wait until the process queue has a packet, block for TIMEOUT_TIME seconds
        packet = process_queue.get(True, TIMEOUT_TIME)
    except Queue.Empty:  # If after blocking there still was not a packet in the queue
        # If we have timed out TIMEOUT_MAX_LIMIT times, then cancel the operation
        if num_timeouts == TIMEOUT_MAX_LIMIT:
            return False, None
        else:
            # If we have timed out less than TIMEOUT_MAX_LIMIT times, then try again with num_timeouts incremented
            print('.'),
            return begin_disconnect(num_timeouts + 1)

    rtp_header = packet.get_header()
    payload = packet.get_payload()

    # Increment and save counters
    client_seq_num_temp = client_seq_num
    server_ack_num_temp = server_ack_num
    calc_client_server_recv_seq_ack_nums(rtp_header, payload)

    if rtp_header.get_ack_num() != client_seq_num:
        client_seq_num = client_seq_num_temp
        server_ack_num = server_ack_num_temp
        return begin_disconnect(num_timeouts + 1)
    else:
        client_state_master = State.FIN_WAIT_2
        return True, num_timeouts

def end_disconnect(num_timeouts):

    global client_state_master
    global client_seq_num
    global server_ack_num

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
            return end_disconnect(num_timeouts + 1)

    rtp_header = packet.get_header()
    payload = packet.get_payload()

    # Increment and save counters
    client_seq_num_temp = client_seq_num
    server_ack_num_temp = server_ack_num
    calc_client_server_recv_seq_ack_nums(rtp_header, payload)

    #if rtp_header.get_ack_num() != client_seq_num:
    #    client_seq_num = client_seq_num_temp
    #    server_ack_num = server_ack_num_temp
    #    return end_disconnect(num_timeouts + 1)
    if rtp_header.get_fin():
        # Change sequence and acknowledge numbers to correct ones before sending to server
        calc_client_server_send_seq_ack_nums(EMPTY_PAYLOAD)

        client_state_master = State.TIME_WAIT

        # Send out the SYN+ACK+HASH packet to complete final handshake part
        send_ack(client_seq_num, server_ack_num)
        return end_disconnect(num_timeouts + 1)
    else:
        return True


def check_packet_seq_ack_nums(rtp_header, payload):

    # Check client ack number matches seq number + payload
    if client_ack_num == rtp_header.get_ack_num():
        return True
    return False


#
# def check_packet_seq_ack_nums(rtp_header, payload):
#
#     # First compare calculated server_seq_nums to recv server_seq_num
#     server_seq_num_correct = False
#     if server_seq_num == rtp_header.get_seq_num():
#         server_seq_num_correct = True
#
#     # Second check client ack number matches seq number
#     client_ack_num_correct = False
#     if client_ack_num == rtp_header.get_ack_num():
#         client_ack_num_correct = True
#
#     return server_seq_num_correct and client_ack_num_correct


def calc_client_server_send_seq_ack_nums(payload):
    global client_ack_num
    # global server_seq_num

    if len(payload) == 0:
        client_ack_num = client_seq_num + 1
    else:
        client_ack_num = client_seq_num + len(payload)

    # server_seq_num = server_ack_num


def calc_client_server_recv_seq_ack_nums(rtp_header, payload):
    global client_seq_num
    global server_ack_num
    # global server_seq_num

    # if server_seq_num == 0:
    #    server_seq_num = rtp_header.get_seq_num()

    client_seq_num = client_ack_num

    if len(payload) == 0:
        server_ack_num = server_seq_num + 1
    else:
        server_ack_num = server_seq_num + len(payload)


# def calc_server_ack_num(rtp_header, payload):
#     global server_seq_num
#     global server_ack_num
#
#     print server_seq_num
#     print server_ack_num
#     # Compute what the server seq and ack numbers should be based on the payload
#     if server_seq_num == 0:
#         server_seq_num = rtp_header.get_seq_num()
#     else:
#         server_seq_num = server_ack_num
#     if len(payload) == 0:
#         server_ack_num = server_seq_num + 1
#     else:
#         server_ack_num = server_seq_num + len(payload)
#     print server_seq_num
#     print server_ack_num


def get(filename):
    global total_packets_rec
    global data

    packets_in_file = 0
    init_payload = 'GET|' + filename
    response, first_seq_num = send_and_wait_for_ack(init_payload, 0)
    if not response:
        print 'Could not retrieve response, GET Failed'
        return
    get_response = response.split("|")
    if not get_response[0] == 'GET' or not get_response[1] == filename:
        print 'Acknowledgment not recognized, check file exists server-side, GET Failed'
    packets_in_file = int(get_response[2])
    data = []
    next_packet_to_rec = 0
    num_timeouts = 0
    total_packets_rec = 0
    for i in range(0, packets_in_file - 1):
        data.append(Packet(RTPHeader(first_seq_num + i * 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0), None, None))
    while True:
        print '{0:.1f}%%'.format(total_packets_rec/packets_in_file)
        curr_num_packets_rec = total_packets_rec
        next_packet_to_rec = wait_for_data_and_acknowledge(datetime.datetime.now(), next_packet_to_rec)
        if next_packet_to_rec == -1:
                break
        if curr_num_packets_rec == next_packet_to_rec:
                num_timeouts += 1
        else:
            # if we did receive reset timeouts
            num_timeouts = 0
        if num_timeouts == TIMEOUT_MAX_LIMIT:
            print 'Server Unresponsive, GET failed'
            break


def wait_for_data_and_acknowledge(time_of_calling, next_packet_to_rec):
    global server_window_size
    global server_seq_num
    global total_packets_rec
    global data

    # Look at all the windows and sequence numbers received
    server_windows_received = []
    server_seq_num_received = []

    while True:
        # Stay in the loop for 5 seconds
        if datetime.datetime.now() > time_of_calling + datetime.timedelta(seconds=5):
            break

        # Try to pull something out of the Queue, block for a second, if there is nothing there, then go to the top
        try:
            new_packet = process_queue.get(True, 1)
        except Queue.Empty:
            continue

        # Look through the packet list to find the packet that the ACK is referencing
        for i in data:
            if i.get_header().seq_num() == new_packet.get_header().get_seq_num():
                total_packets_rec += 1
                server_windows_received.append(new_packet.get_header().get_window())
                server_seq_num_received.append(new_packet.get_header().get_seq_num())
                i.payload = new_packet.get_payload()
                send(1, 0, 0, 0, 0, i.get_header().seq_num() + len(i.get_header()))
    server_seq_num = max(server_seq_num_received)
    server_window_size = min(server_windows_received)
    for i in range(next_packet_to_rec, len(data) - 1):
        if not data[i].get_payload():
            return i
    return -1


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
            return None, None
        else:
            # If we have timed out less than TIMEOUT_MAX_LIMIT times, then try again with num_timeouts incremented
            print('.'),
            return send_and_wait_for_ack(payload, num_timeouts + 1)
    if packet.get_header().get_ip() == net_emu_ip_address_long and \
        packet.get_header().get_port() == net_emu_port and \
            packet.get_header().get_ack_num() == client_seq_num + len(payload) + 1 and \
            packet.get_header().get_ack() and not packet.get_header().get_nack:
        return packet.get_payload(), packet.get_header.get_seq_num() + len(payload)
    else:
        print('.'),
        return send_and_wait_for_ack(payload, 0)


def post(filename):
    global total_packets_sent
    global packet_list

    try:
        file_handle = open(filename, 'rb')
    except IOError:
        print "Could not open file: {0}".format(filename)
        return
    del packet_list[:]  # clear out the list of packets
    while True:
        data = file_handle.read(1024)
        if not data:
            break
        packet_list.append(Packet(RTPHeader(0, 0, 0, 0, 0, 0, 0, 0, net_emu_ip_address_long, net_emu_port), data,
                                  False))
    file_handle.close()
    init_payload = 'POST|{0}|{1}'.format(filename, str(len(packet_list)))
    if not send_and_wait_for_ack(init_payload, 0):
        print 'Could not retrieve response, POST Failed'
        return
    else:
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

            # Use temp variable to see if we actually received any
            curr_num_packets_sent = total_packets_sent

            # wait_for_acks processes all the packets received in the 5 seconds after sending the window,
            # and sets the next packet to send
            next_packet_to_send = wait_for_acks(datetime.datetime.now(), next_packet_to_send)

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


def wait_for_acks(time_of_calling, next_packet_to_send):
    global server_window_size
    global server_seq_num
    global total_packets_sent
    global packet_list

    # Look at all the windows and sequence numbers received
    server_windows_received = []
    server_seq_num_received = []

    while True:
        # Stay in the loop for 5 seconds
        if datetime.datetime.now() > time_of_calling + datetime.timedelta(seconds=5):
            break

        # Try to pull something out of the Queue, block for a second, if there is nothing there, then go to the top
        try:
            new_packet = process_queue.get(True, 1)
        except Queue.Empty:
            continue

        # Look through the packet list to find the packet that the ACK is referencing
        for i in packet_list:
            if i.get_header().seq_num() + len(i.get_payload()) == new_packet.get_header().get_ack_num():
                i.acknowledged = True
                total_packets_sent += 1
                server_windows_received.append(new_packet.get_header().get_window())
                server_seq_num_received.append(new_packet.get_header().get_seq_num())
    server_seq_num = max(server_seq_num_received)
    server_window_size = min(server_windows_received)
    for i in range(next_packet_to_send, len(packet_list) - 1):
        if not packet_list[i].get_acknowledged():
            return i
    return -1


def send(ack, syn, fin, nack, payload, seq_num, ack_num):

    # Calculate checksum on rtp_header and payload with a blank checksum
    checksum = 0
    rtp_header_obj = RTPHeader(seq_num, ack_num, checksum, client_window_size, ack, syn, fin, nack,
                               CLIENT_IP_ADDRESS_LONG, client_port)
    packed_rtp_header = pack_rtpheader(rtp_header_obj)
    packet = packed_rtp_header + payload
    checksum = sum(bytearray(packet))

    # Install checksum into rtp_header and package up with payload
    rtp_header_obj = RTPHeader(seq_num, ack_num, checksum, client_window_size, ack, syn, fin, nack,
                               CLIENT_IP_ADDRESS_LONG, client_port)
    packed_rtp_header = pack_rtpheader(rtp_header_obj)
    packet = packed_rtp_header + payload

    if is_debug:
        print "Sending:"
        print '\tClient Seq Num:\t' + str(seq_num)
        print '\tServer ACK Num:\t' + str(ack_num)
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


def pack_rtpheader(rtp_header):

    flags = pack_bits(rtp_header.get_ack(), rtp_header.get_syn(), rtp_header.get_fin(), rtp_header.get_nack())
    rtp_header = struct.pack('!LLHLBLH', rtp_header.get_seq_num(), rtp_header.get_ack_num(), rtp_header.get_checksum(),
                             rtp_header.get_window(), flags, rtp_header.get_ip(), rtp_header.get_port())

    return rtp_header


def unpack_rtpheader(packed_rtp_header):
    #global server_window_size
    #global server_port
    global server_seq_num

    unpacked_rtp_header = struct.unpack('!LLHLBLH', packed_rtp_header)  # 21 bytes
    server_seq_num = unpacked_rtp_header[0]
    client_ack_num_test = unpacked_rtp_header[1]
    checksum = unpacked_rtp_header[2]
    server_window_size_temp = unpacked_rtp_header[3]
    flags = unpacked_rtp_header[4]
    ack, syn, fin, nack = unpack_bits(flags)
    server_ip_address_long = unpacked_rtp_header[5]
    server_port_temp = unpacked_rtp_header[6]
    rtp_header_obj = RTPHeader(server_seq_num, client_ack_num_test, checksum, server_window_size_temp, ack, syn,
                               fin, nack, server_ip_address_long, server_port_temp)

    if is_debug:
        print "Unpacking Header:"
        print '\tServer Seq Num:\t' + str(server_seq_num)
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


def send_syn(seq_num, ack_num):

    send(0, 1, 0, 0, EMPTY_PAYLOAD, seq_num, ack_num)


def send_synack(payload, seq_num, ack_num):

    if payload != EMPTY_PAYLOAD:
        payload = create_hash(payload)

    send(1, 1, 0, 0, payload, seq_num, ack_num)


def send_ack(seq_num, ack_num):
    send(1, 0, 0, 0, EMPTY_PAYLOAD, seq_num, ack_num)


def send_nack(seq_num, ack_num):
    send(0, 0, 0, 1, EMPTY_PAYLOAD, seq_num, ack_num)


def send_fin(seq_num, ack_num):
    send(0, 0, 1, 0, EMPTY_PAYLOAD, seq_num, ack_num)


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
    EMPTY_PAYLOAD = ''
    QUEUE_MAX_SIZE = 10

    # Client
    client_window_size = 1
    client_port = ''
    CLIENT_IP_ADDRESS = socket.gethostbyname(socket.gethostname())
    CLIENT_IP_ADDRESS_LONG = struct.unpack("!L", socket.inet_aton(CLIENT_IP_ADDRESS))[0]
    client_seq_num = 0  # random.randint(0, 2**32-1)  # Todo - fix when done testing, Should we also consider wrap around?
    client_ack_num = client_seq_num
    client_timer = ''
    TIMEOUT_MAX_LIMIT = 25
    TIMEOUT_TIME = 1
    client_state_master = State.SYN_SENT
    packet_list = []
    is_connected = False
    is_disconnected = False
    total_packets_sent = 0
    fin_listen_termination_lock = threading.Lock()
    fin_terminate = False

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
    process_queue = Queue.Queue(maxsize=QUEUE_MAX_SIZE)
    total_packets_rec = 0
    data = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        print 'Failed to create socket'
        sys.exit()

    main(sys.argv[1:])
