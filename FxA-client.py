import socket
import sys


def connect(client_port, ip_address, net_emu_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', client_port))
    # send()


def main(argv):
    if len(argv) != 3:
        print("Correct usage: FxA-Client X A P")
        sys.exit(1)

    client_port = argv[0]
    ip_address = argv[1]
    net_emu_port = argv[2]
    is_connected = False
    x = ''
    window = 0
    state = State.CLOSED

    try:
        client_port = int(client_port)
    except ValueError:
        print('Invalid client port number %s' % argv[0])
        sys.exit(1)

    if client_port % 2 == 1:
        print('Client port number: %d was not even number' % client_port)
        sys.exit(1)

    try:
        ip_address = socket.inet_aton(ip_address)
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
        if x == 'connect':
            is_connected = connect(client_port, ip_address, net_emu_port)
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
                    window = int(y[1])
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
    main(sys.argv[1:])
