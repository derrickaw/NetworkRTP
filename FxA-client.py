import sys
import socket


def main(argv):
    isConnected = False
    clientport = ''
    ipaddress = ''
    netemuport = ''
    x = ''
    if len(argv) != 3:
        print "Correct usage: FxA-Client X A P"
        sys.exit(1)
    if int(argv[0]) % 2 == 1:
        print()
    clientport = int(argv[0])
    ipaddress = argv[1]
    netemuport = argv[2]
    try:
        socket.inet_aton(ipaddress)
    except socket.error:
        print "Invalid IP notation in param A"
        sys.exit(1)
    # TODO check if port is open!

    print('Command Options:')
    print('connect\t\t|\tConnects to the FxA-server')
    print('get F\t\t|\tRetrieve file F from FxA-server')
    print('post F\t\t|\tPushes file F to the FxA-server')
    print("window W\t|\tSets the maximum receiver's window size")
    print("disconnect\t|\tDisconnect from the FxA-server\n")

    while x != 'disconnect':
        x = raw_input('Please enter command:')
        if x == 'connect':
            # TODO connect() call
            isConnected = True
        elif x == 'disconnect':
            # TODO disconnect() call
            break
        else:
            y = x.split(" ")
            if len(y) != 2:
                print("Invalid command: get, post, window require secondary parameter")
                break
            if y[0] == 'get':
                if isConnected:
                    # TODO get()
                    print('get')
                else:
                    print('get not valid without existing connection')
            elif y[0] == 'post':
                if isConnected:
                    # TODO post()
                    print('post')
                else:
                    print('post not valid without existing connection')
            elif y[0] == 'window':
                if isConnected:
                    # TODO window()
                    print('window')
                else:
                    print('window not valid without existing connection')
            else:
                print("Invalid command")

if __name__ == "__main__":
    main(sys.argv[1:])
