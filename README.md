# NetworkingRTP
CS3251 Fall 2015 Programming Assignment 2

Elliott Childre
rchildre3@gatech.edu
rchildre3

Derrick Williams
derrickw@gatech.edu
dwilliams306

## Usage
To run the FxA application use the following commands

### Server

#### Startup

Py FxA-server.py X A P

The command-line arguments are:

X: the port number at which the FxA-server’s UDP socket should bind to (odd number)
A: the IP address of NetEmu
P: the UDP port number of NetEmu

#### Commands
Command: "window W"
	Set the maximum receiver’s window-size at the FxA-Server
	W: The window-size (in segments).

Command: "terminate"
	Shut-down FxA-Server gracefully.

### Client

#### Startup

Py FxA-client.py X A P

The command-line arguments are:

X: the port number at which the FxA-client’s UDP socket should bind to (even number). Please remember that this port number should be equal to the server’s port number minus 1.
A: the IP address of NetEmu
P: the UDP port number of NetEmu

#### Commands
Command: "connect"
	The FxA-client connects to the FxA-server (running at the same IP host)

Command: "get F"
	The FxA-client downloads a file from the server (if it exists in the same directory with the FxA-server program)
	F: The File to retrieve
	REQUIRES EXISTING CONNECTION

Command: "post F"
	The FxA-client uploads a file to the server (if F exists in the same directory with the FxA-client program)
	F: The File to upload
	REQUIRES EXISTING CONNECTION

Command: "window W"
	Set the maximum receiver’s window-size at the FxA-client
	W: The window-size (in segments).

Command: "disconnect"
	The FxA-client terminates gracefully from the FxA-server
	REQUIRES EXISTING CONNECTION