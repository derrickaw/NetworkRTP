import socket
import sys
import threading
import Queue
import struct
from threading import Timer



def main(argv):

    if len(argv) != 3:
        print("Correct usage: FxA-Server X A P")
        sys.exit(1)

    server_port = argv[0]
    ip_address = argv[1]
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
        ip_address = socket.inet_aton(ip_address)
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

    # Bind to server port
    sock.bind(('', server_port))

    # Check for user input, start packet collection, and start processing queue
    try:
        t_user = threading.Thread(target=user_input,args=())
        t_user.start()
        t_recv = threading.Thread(target=recv_packet,args=())
        t_recv.daemon = True
        t_recv.start()
        t_proc = threading.Thread(target=proc_packet,args=())
        t_proc.daemon = True
        t_proc.start()

    except:
        print "Error"

    t_user.join()
    sock.close()

    #t_term.set()




def recv_packet():
    while True:
        try:
            packet = sock.recvfrom(buff_size)
            queue.put(packet)
        except socket.error, msg:
            continue

def proc_packet():
    while True:
        while not queue.empty():
            packet = queue.get()
            data = packet[0]
            #print len(data)
            data = struct.unpack('!LLHBLH', data)
            #print data

            sock.sendto(packet[0],packet[1])



def connection_setup():
    pass



def user_input():
    global window_size
    global terminate
    command_input = ''

    # Server Command Instructions
    print('Command Options:')
    print("window W\t|\tSets the maximum receiver's window size")
    print("terminate\t|\tShut-down FxA-Server gracefully\n")

    # Loop for commands from server user
    while command_input != 'terminate':
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
    terminate = True
    print("Server closing")



def send(param, param1, param2):
    pass


def timeout(args):
    pass


def acknowledge():
    pass


def checkhash():
    pass


class Connection:

    def __init__(self, sender_ip, sender_port):
        self.state = State.SYN_RECEIVED
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        self.timer = Timer(10, timeout)
        self.timer.start()

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
    window_size = 0
    terminate = False
    queue = Queue.Queue(maxsize=15000)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t_term = threading.Event()


    main(sys.argv[1:])
