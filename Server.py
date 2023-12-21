from Colors import Colors
import socket
from RSA import RSA_Key
import ipaddress
from Cryptodome.PublicKey import RSA

#Library for p2p networking
from threading import Thread, active_count#,Lock

#SERVER FINALS
MSG_DISS = b"[DISCONNECT]"   #message to safely disconnect from server
MSG_CONN = "[CONNECT]"
PK_LEN = 799

"""
    class SERVER 
    ------------
    handles all the interworkings of the p2p
    This includes connecting to clients and accepting
    connections from clients
""" 
class Server():
    """
        Constructor
        -----------
        Takes in RSA_Key objects to use as personal keychain for 
        decrypting messages and to send to other users for encrypting messages.
        This constructor also sets up arrays to be used in order to keep track of
        which clients are hosting and which clients are clients.
        param: RSA_KEY (personal priv/pub keys)
        returns: void
    """
    def __init__(self, keys:RSA_Key, server_ip:str, port: int):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((server_ip, port))
        print(f"{Colors.OKCYAN}\r[SERVER] ESTABLISHED @ {server_ip}:{port}{Colors.ENDC}\n:", end="")
        self.keys = keys
        self.clients = []   # (ip,port)
        self.keychain = {} # (ip,port) -> (socket,public_key)
        self.messages = {} # (ip,port) -> [ (ip,port) , messages:str ]
        self.contacts = {} # name:str -> (ip,port)
        self.running = True
    
    """
        Handle Client
        -------------
        This handles all incomming messages and is synchronous for every connection
        param: 
            conn: is the socket object
            addr:
        returns: void
    """
    def handle_client(self, conn:socket, addr:tuple[str,int], isClient:bool=False):
        #run while client is connected (used for graceful disconnect)
        connected = True
        #upon connection, go through handshake first
        if not self.handshake(isClient=isClient, client=conn, addr=addr):
            conn.close()
            return False
        while connected:
            #wait and receive messages
            message = None
            try:
                message = self.receive_message(conn=conn)
                #if client is disconnecting, exit gracefully
                if message ==  MSG_DISS:
                    break
            #Catch error on malformed packet recieve_message throws value error
            except ValueError:
                print(f"{Colors.FAIL}ERROR: CORRUPT MESSAGE RECEIVED{Colors.ENDC}")
            #check for error on file descriptor, helps catch error when exiting
            except OSError:
                if self.running:
                    print(f"{Colors.FAIL}ERROR: FAILED WAITING FOR MESSAGE FROM {addr[0]}:{addr[1]}{Colors.ENDC}")
            #if no message sent (usually on connection), ignore
            if message == None:
                continue
            print(f"{Colors.OKCYAN}\r[SERVER] RECEIVED MESSAGE FROM {addr[0]}{Colors.ENDC}\n:", end="")
            self.messages.get(addr).append((addr,message))
            #print(message)
        self.clients.remove(addr)
        print(f"{Colors.OKCYAN}\r[SERVER] CLIENT {addr[0]}:{addr[1]} HAS DISCONNECTED{Colors.ENDC}\n:", end="")
        conn.close()

    """
        Connect Client
        --------------
        Used to connect to other clients and initiate a connection
        param:
            ip_address: who to connect to
            port: which port to use default use the PORT final var
    """
    def connect_to_client(self, ip_address:str, port:int) -> bool | None:
        #check if IP is a valid IP address
        try:
            ipaddress.ip_address(ip_address)
        except ValueError as ve:
            print(f"{Colors.FAIL}ERROR: MALFORMED IP ADDRRESS '{ip_address}'{Colors.ENDC}")
            return None
        
        #check if valid port number
        try:
            port = int(port)
            if port >= 65525 or port < 0:
                print(f"{Colors.FAIL}ERROR: INVALID PORT NUMBER '{port}'{Colors.ENDC}")
                return None
        except ValueError:
            print(f"{Colors.FAIL}ERROR: PORT NUMBER WAS NOT A VALID INTEGER'{port}'{Colors.ENDC}")
            return None
        
        #create a socket object
        client = socket.socket()
        try:
            #attempt connection to ip_address:port
            client.connect((ip_address, int(port)))
        except Exception:
            #connection failed, print error and return 
            print(f"{Colors.FAIL}ERROR: CONNECTION TO {ip_address}:{port} FAILED{Colors.ENDC}")
            client.close()
            return None
        
        #check if server is still running
        # KEEP AFTER CONNECTION ESTABLISHED TO PROPERLY TERMINATE SERVER
        if not self.running:
            client.close()
            return None
        
        #attempt handshake to establish secure communications
        thread = Thread(target=self.handle_client, args=(client, (ip_address, port), True))
        thread.start()
        return True
    
   
    """
        Function Handshake
        ==================
        Allows a way to exchange pub keys and test for corruption upon connection
        client
        sending pk -> recieve pk -> send test message -> receive test message
        server
        receiving pk -> sending pk -> receive test message -> sending test message
    """
    def handshake(self, isClient:bool, client:socket, addr:tuple[str,int]) -> bool:
        public_key = None
        if isClient:
            #send public key to server
            client.send(self.keys.public_bytes.export_key(format='PEM', passphrase=None, pkcs=1))
            #wait for 'host' public key
            public_key = RSA.import_key(client.recv(PK_LEN))
            #send test message to server
            #change to send all at once to avoid data
            client.send(b"".join(self.keys.EncryptMessage(message=MSG_CONN, public_bytes=public_key)))
            #wait for 'host' test message
            if not self.receive_message(conn=client) == MSG_CONN:
                return False
        else:
            #receive the public key from client
            public_key = RSA.import_key(client.recv(PK_LEN))
            #send public key to client
            client.send(self.keys.public_bytes.export_key(format='PEM', passphrase=None, pkcs=1))
            #receive the test message
            if not self.receive_message(conn=client) == MSG_CONN:
                return False
            #send test message
            client.send(b"".join(self.keys.EncryptMessage(message=MSG_CONN, public_bytes=public_key)))

        print(f"{Colors.OKCYAN}\r[SERVER] CONNECTION ESTABLISHED {addr[0]}:{addr[1]}{Colors.ENDC}\n:", end="")
        
        #update the metadata for the message threads and connection
        self.keychain.update({addr:(client, public_key)})
        self.messages.update({addr:[]})
        self.clients.append(addr)
        return True

    """
        Send Message
        ============
        Sends message to anyone who already has an established connection
        Param: 
            addr: destination address (ip_address, port) tuple 
            message: the message to be sent (str)
    """
    def send_message(self, addr:tuple[str,int], message:str) -> bool:
        socket, pub_key = self.keychain.get(addr)
        try:
            socket.send(b"".join(self.keys.EncryptMessage(message, pub_key)))
        except Exception:
            print(f"{Colors.FAIL}ERROR: FAILED SENDING MESSAGE TO {addr[0]}:{addr[1]}{Colors.ENDC}")
            return False
        return True

    """
        Function Receive Message
        =========================
        Handles the de-encapsulation of a 'packet' passed in 
    """
    def receive_message(self, conn:socket) -> str:
        aes_key = conn.recv(512)
        #if message data is blank, do not process
        if not aes_key:
            return None
        if aes_key == MSG_DISS:
            return MSG_DISS
        if len(aes_key) != 512:
            #print(f"{Colors.FAIL}ERROR: CORRUPT MESSAGE RECEIVED{Colors.ENDC}")
            raise ValueError
        nonce = conn.recv(16)
        tag = conn.recv(16)
        header = conn.recv(4) #header
        cipher_text = conn.recv( int.from_bytes(header, "big") )
        message = self.keys.DecryptMessage((aes_key,nonce,tag,cipher_text))
        if message == None:
            raise ValueError
        return message
    
    """
        prints out existing connections both clients and servers
    """
    def get_connections(self) -> None:
        print(f"Active Connections:")
        for i,connections in enumerate(self.clients):
            print(f"\t{i+1}) {connections[0]}:{connections[1]}")

    """
        Function Start
        ==============
        Starts up the server side and starts listening for incoming connections
        Must be killed by setting running to False and then sending a connection request
        server.accept() hangs otherwise
        param: None
        returns: None
    """
    def start(self) -> None:
        self.server.listen()
        print(f"{Colors.OKCYAN}\r[SERVER] LISTENING FOR NEW CONNECTIONS{Colors.ENDC}\n:", end="")
        while self.running:
            conn, addr = self.server.accept()
            if not self.running:
                continue
            print(f"{Colors.OKCYAN}\r[SERVER] CONNECTION REQUEST {addr[0]}:{addr[1]}{Colors.ENDC}\n:", end="")
            thread = Thread(target=self.handle_client, args=(conn,addr))
            thread.start()
            print(f"{Colors.OKCYAN}\r[ACTIVE CONNECTIONS] {active_count()-2}{Colors.ENDC}\n:", end="")
        print(f"{Colors.OKCYAN}\r[SERVER] NO LONGER LISTENING{Colors.ENDC}\n:", end="")
