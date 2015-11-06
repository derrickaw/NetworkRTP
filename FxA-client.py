import sys
import socket


def main(argv):
    if len(argv) != 3:
        print "Correct usage: FxA-Client X A P"
        sys.exit(1)

    clientport = argv[0]
    ipaddress = argv[1]
    netemuport = argv[2]
    isConnected = False
    x = ''

    try:
        clientport = int(clientport)
    except ValueError:
        print('Invalid client port number %s' % argv[0])
        sys.exit(1)

    if clientport % 2 == 1:
        print('Client port number: %d was not even number' % clientport)
        sys.exit(1)

    try:
        ipaddress = socket.inet_aton(ipaddress)
    except socket.error:
        print("Invalid IP notation: %s" % argv[1])
        sys.exit(1)
        # TODO check if port is open!

    try:
        netemuport = int(netemuport)
    except ValueError:
        print('Invalid NetEmu port number: %s' % argv[2])
        sys.exit(1)

    # print 'print type(clientport)' + str(type(clientport))
    # print 'print type(ipaddress)' + str(type(ipaddress))
    # print 'print type(netemuport)' + str(type(netemuport))

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
            if y[0] == 'get':
                if len(y) != 2:
                    print("Invalid command: get requires secondary parameter")
                    continue
                if isConnected:
                    # TODO get()
                    print('get')
                else:
                    print('get not valid without existing connection')
            elif y[0] == 'post':
                if len(y) != 2:
                    print("Invalid command: post requires secondary parameter")
                    continue
                if isConnected:
                    # TODO post()
                    print('post')
                else:
                    print('post not valid without existing connection')
            elif y[0] == 'window':
                if len(y) != 2:
                    print("Invalid command: window requires secondary parameter")
                    continue
                if isConnected:
                    # TODO window()
                    print('window')
                else:
                    print('window not valid without existing connection')
            else:
                print("Command not recognized")

if __name__ == "__main__":
    main(sys.argv[1:])
