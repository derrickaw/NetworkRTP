#!python2

import sys
import socket


def main(argv):
    if len(argv) != 3:
        print("Correct usage: FxA-Client X A P")
        sys.exit(1)

    serverport = argv[0]
    ipaddress = argv[1]
    netemuport = argv[2]
    x = ''
    window = 0

    try:
        serverport = int(serverport)
    except ValueError:
        print('Invalid server port number %s' % argv[0])
        sys.exit(1)

    if serverport % 2 == 0:
        print('Server port number: %d was not an odd number' % serverport)
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

    print('Command Options:')
    print("window W\t|\tSets the maximum receiver's window size")
    print("terminate\t|\tShut-down FxA-Server gracefully\n")

    while x != 'terminate':
        x = raw_input('Please enter command:')
        if x == 'terminate':
            # TODO terminate() call
            break
        else:
            y = x.split(" ")
            if y[0] == 'window':
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

if __name__ == "__main__":
    main(sys.argv[1:])
