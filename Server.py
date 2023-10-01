#Crypto Libraries
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA512
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes

#Library for handling password input
import getpass

#other libraries
import time
import re

#Library for p2p networking
import socket
import threading
import ipaddress

#SERVER FINALS
PORT = 4444 #port to run the server on
SERVER_IP = socket.gethostbyname(socket.gethostname()) #server ip
MSG_DISS = b"[DISCONNECT]"   #message to safely disconnect from server
HEADER = 4
MAX_MESSAGE_LEN = 256**HEADER-1
FORMAT = "utf-8"

#CRYPTO FINALS
RSA_BITS = 4096
HASH_ALGO = SHA512
AES_BITS = 256
CIPHER_MODE = AES.MODE_GCM
PKI_FILE_FORMAT = "PEM"

#text colors
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m' #yellow
    FAIL = '\033[91m' #red
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

"""
    Class Config
    ============
    handles the configuration file of where keys are stored
    line1: priv and pub keys of self
    line2: file location of other user's public keys
"""
class Config():
    def __init__(self):
        with open(".config", "r") as config:
            #line 1: basic home directory of files
            self.dir = config.readline().split("=")[1].strip()
            #line 2: location/name of keychain file
            self.keychain = config.readline().split("=")[1].strip()
            #line 3: name of private key file
            self.priv = config.readline().split("=")[1].strip()
            #line 4: name of public key file
            self.pub = config.readline().split("=")[1].strip()
            #convert private/public key file value to None if empty
            if(self.priv == ""):
                self.priv = None
            if(self.pub == ""):
                self.pub = None

"""
    Class RSA_Key
    =============
    Holds the public and/or matching private key
    params:
        public file  : file location holing the public key to be imported
        private file : file location holing the private key to be imported
        public key   : bit string representing the public key to be imported
        private key  : bit string representing the private key to be imported
"""
class RSA_Key():

    def __init__(self, config:str, *, public_file:str=None, private_file:str=None, public_bytes:str=None, private_bytes:str=None) -> None:
        #initialize values
        self.public_bytes = None
        self.private_bytes = None

        #check arguements passed (can't pass in file location and byte representation for same key type due to overwrites)
        if public_bytes and public_file:
            print(f"{bcolors.FAIL}Too many paramaters for public key passed. Only pass a file or a string{bcolors.ENDC}")
        if private_bytes and private_file:
            print(f"{bcolors.FAIL}Too many paramaters for private key passed. Only pass a file or a string{bcolors.ENDC}")
        
        #If key bytes are passed in, set as key value
        if public_bytes:
            self.public_bytes = public_bytes
        if private_bytes:
            self.private_bytes = private_bytes

        #Import keys from file
        if public_file:
            self.ImportKey(public_file)
        if private_file:
            self.ImportKey(private_file, is_private=True)
    
    """
        Function Gen Keys
        ================
        Generates new RSA keys and returns the byte representation
        parameters: None
        return:     public key, private key
    """
    def GenKeys(self) -> None:
        #generate RSA 4096 private key
        self.private_bytes = RSA.generate(bits=RSA_BITS)
        #use private key to generate public key
        self.public_bytes = self.private_bytes.public_key()

    """
        Function Save Key
        ==================
        Export key to file and from passed in byte string
        param: key to be saved
        returns: True if successful, None if error
    """
    def ExportKey(self, file:str, key:str):
        pass1 = None
        pem = b""
        if(key.has_private()):
            #get password to encrypt the PEM file
            print(f"{bcolors.WARNING}You are exporting a private key, please provide \na secure password to protect your private key{bcolors.ENDC}")
            pass1 = getpass.getpass("Enter password for private key  : ")
            pass2 = getpass.getpass("Confirm password for private key: ")
            if(pass1 != pass2):
                print(f"{bcolors.FAIL}ERROR: PASSWORDS DO NOT MATCH (keys were not generated){bcolors.ENDC}")
                return None
        #make sure to encrypt private key
        if(key.has_private()):
            pem = key.export_key(format=PKI_FILE_FORMAT, passphrase=pass1, pkcs=8)
        else:
            pem = key.export_key(format=PKI_FILE_FORMAT)
        #write pem file
        try:
            with open(file, "wb") as pem_file:
                pem_file.write(pem)
        except Exception as e:
            print(f"{bcolors.FAIL}ERROR: OPENING OR WRITTING TO PEM FILE{bcolors.ENDC}")
            return None
        #return successful or not
        return True
    
    """
        Function Import Key
        ===================
        Import key from file and return the byte string
        param: file to read from
        returns: void
    """
    def ImportKey(self, file:str, *, is_private:bool=False):
        pass1=None
        
        try:
            with open(file, "r") as pem_file:
                #get password if private key
                if(is_private):
                    pass1 = getpass.getpass("Enter password for private key: ")
                #read key from file 
                key_bytes = RSA.import_key(pem_file.read(), passphrase=pass1)
                #set value of respected key
                if is_private:
                    self.private_bytes = key_bytes
                else:
                    self.public_bytes = key_bytes
                return True
        except ValueError as ve:
            print(f"{bcolors.FAIL}ERROR: INCORRECT PASSWORD{bcolors.ENDC}")   
        except Exception as e:
            print(f"{bcolors.FAIL}ERROR: KEY NOT READ FROM FILE '{file}' {bcolors.ENDC}")
        return None
    
    """
        Function Encrypt Message
        ========================
        Encrypts the message using the class' public key
        param: message to be encrypted
        returns: string representing the cipher text
    """
    def EncryptMessage(self, message:str) -> (str, str, str, str):
        #make sure message length is short enough to be sent in one message
        if(len(message) > MAX_MESSAGE_LEN):
            print(f"{bcolors.FAIL}ERROR: MESSAGE IS TOO LONG, PLEASE SHORTEN TO LESS THAN {MAX_MESSAGE_LEN:,} CHARACTERS{bcolors.ENDC}")
            input("PRESS ENTER TO CONTINUE")
            return None
        #generate session key
        session_key = get_random_bytes(AES_BITS//8)

        if(self.public_bytes is None):
            print(f"{bcolors.FAIL}ERROR: TRYING TO ENCRYPT WITH NULL KEY{bcolors.ENDC}")
            return None
        
        #encrypt session key using asymetric encryption (public key)
        try:
            cipher_rsa = PKCS1_OAEP.new(self.public_bytes, hashAlgo=HASH_ALGO)
            enc_session_key = cipher_rsa.encrypt(session_key)
        except Exception:
            print(f"{bcolors.FAIL}ERROR: RSA ENCRYPTION{bcolors.ENDC}")
            return None
        
        #use AES and session_key to encrypt message
        try:
            cipher_aes = AES.new(session_key, CIPHER_MODE)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode(FORMAT))
        except Exception:
            print(f"{bcolors.FAIL}ERROR: AES ENCRYPTION{bcolors.ENDC}")
            return None
        #print(f">%x\n>%x\n>%x\n>%x\n", enc_session_key, cipher_aes.nonce, tag, len(ciphertext).to_bytes(HEADER,'big'), ciphertext)

        #print(len(enc_session_key), len(cipher_aes.nonce), len(tag), len(ciphertext).to_bytes(HEADER,'big'), len(message))
        return (enc_session_key, cipher_aes.nonce, tag, len(ciphertext).to_bytes(HEADER,'big'), ciphertext)
    
    """
        Function Decrypt Message
        ========================
        Decrypts the message using the class' private key
        param: ciphertext to be decrypted
        returns: string representing the message
    """
    def DecryptMessage(self, ciphertext:str) -> str:
        enc_session_key = ciphertext[0]
        nonce = ciphertext[1]
        tag = ciphertext[2]
        ciphertext = ciphertext[4]

        #check if key is not NULL
        if(self.private_bytes is None):
            print(f"{bcolors.FAIL}ERROR: ATTEMPTING DECRYPTION WITH NULL KEY{bcolors.ENDC}")
            return None
        
        # Decrypt the session key with the private RSA key
        try:
            cipher_rsa = PKCS1_OAEP.new(self.private_bytes, hashAlgo=HASH_ALGO)
            session_key = cipher_rsa.decrypt(enc_session_key)
        except Exception:
            print(f"{bcolors.FAIL}ERROR: RSA DECRYPTION{bcolors.ENDC}")
            return None
        
        # Decrypt the data with the AES session key
        try:
            cipher_aes = AES.new(session_key, CIPHER_MODE, nonce)
            message = cipher_aes.decrypt_and_verify(ciphertext, tag)
        except Exception:
            print(f"{bcolors.FAIL}ERROR: AES DECRYPTION{bcolors.ENDC}")
            return None
        
        return message.decode(FORMAT)
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
    def __init__(self, keys:RSA_Key):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((SERVER_IP, PORT))
        print(f"{bcolors.OKCYAN}[SERVER] ESTABLISHED @ {SERVER_IP}:{PORT}{bcolors.ENDC}")
        self.keys = keys
        self.connections = []
        self.clients = []
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
    def handle_client(self, conn:socket, addr ):
        if self.running:
            print(f"{bcolors.OKCYAN}[NEW CONNECTION]: {addr}{bcolors.ENDC}")
        
        #run while client is connected (used for graceful disconnect)
        connected = True
        while connected:
            key = conn.recv(512)
            #if message data is blank, do not process
            if not key:
                continue
            if key == MSG_DISS:
                break
            if len(key) != 512:
                print(f"{bcolors.FAIL}ERROR: CORRUPT MESSAGE RECEIVED{bcolors.ENDC}")
                continue
            nonce = conn.recv(16)
            tag = conn.recv(16) #
            header = conn.recv(4) #header
            cipher_text = conn.recv( int.from_bytes(header, "big") )
            message = self.keys.DecryptMessage((key,nonce,tag,cipher_text))
            print(f"Message received: {message}")
        conn.close()

    """
        Connect Client
        --------------
        Used to connect to other clients and initiate a connection
        param:
            ip_address: who to connect to
            port: which port to use default use the PORT final var
    """
    def connect_client(self, ip_address, port=PORT):
        try:
            ipaddress.ip_address(ip_address)
        except ValueError as ve:
            print(f"{bcolors.FAIL}ERROR: MALFORMED IP ADDRRESS '{ip_address}'{bcolors.ENDC}\n{ve}")
            return
        client = socket.socket()
        try:
            #attempt connection to ip_address:port
            client.connect((ip_address, int(port)))
        except ValueError:
            print(f"{bcolors.FAIL}ERROR: MALFORMED PORT NUMBER '{port}'{bcolors.ENDC}")
            client.close()
            return None
        except:
            #connection failed, print error and return 
            print(f"{bcolors.FAIL}ERROR: CONNECTION TO {ip_address}:{port} FAILED{bcolors.ENDC}\n")
            client.close()
            return None
        #connection successful, keep track of active connection
        self.connections.append(client)
        return True
    
    """
        Send Message

    """
    def send_message(self, conn:socket, addr):
        pass

    """
        prints out existing connections both clients and servers
    """
    def get_connections(self):
        pass

    """
        Function Start
        ==============
        Starts up the server side and starts listening for incoming connections
        Must be killed by setting running to False and then sending a connection request
        server.accept() hangs otherwise
        param: None
        returns: None
    """
    def start(self):
        self.server.listen()
        print(f"{bcolors.OKCYAN}[SERVER] LISTENING FOR NEW CONNECTIONS{bcolors.ENDC}")
        while self.running:
            conn, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(conn,addr))
            thread.start()
            if self.running: 
                print(f"{bcolors.OKCYAN}[ACTIVE CONNECTIONS] {threading.active_count()-2}{bcolors.ENDC}")

"""
    Function Print Menu
    ====================
    Prints out the main menu of the basic user interface
    param: the keys of the user
    returns: None
"""
def print_menu(my_keys:RSA_Key):
    has_pub = not my_keys.public_bytes is None
    has_priv = not my_keys.private_bytes is None
    print("{0:40s}".format("Welcome to the p2p server"))
    print("{0:40s}{2:5s}{1:20s}".format("1) Import Keys"," : Public Key Loaded",str(has_pub)))
    print("{0:40s}{2:5s}{1:20s}".format("2) Export Keys"," : Private Key Loaded",str(has_priv)))
    print("{0:40s}".format("3) Generate new keys"))
    print("{0:40s}".format("4) Start Session"))
    print("{0:40s}".format("5) View Session"))
    print("{0:40s}".format("6) Clear Session"))
    print("{0:40s}".format("9) Exit"))

def import_keys(my_keys):
    #get parameters for importing keys from user
    file_name = input("What is the name of the pem file you wish to import?\n:").strip()
    is_priv = input("Is this a private key? [y/Y/n/N]\n:").strip()
    #convert str var into boolean var
    is_priv = is_priv == "y" or is_priv == "Y" 
    #import keys into system
    if(my_keys.ImportKey(file_name, is_private=is_priv)):
        print(f"{bcolors.OKGREEN}Successful import!{bcolors.ENDC}")

def export_keys(my_keys):
    #get parameters for exporting keys from user
    file_name = input("What is the name of the pem file you wish to export to?\n:")
    key_type = input("Do you wish to export the public or private key? [public/private]\n:")
    #check if public or private key and then export
    if key_type == "public":
        if(my_keys.ExportKey(file_name, my_keys.public_bytes)):
            print(f"{bcolors.OKGREEN}Successful export{bcolors.ENDC}")
    elif key_type == "private":
        if(my_keys.ExportKey(file_name, my_keys.private_bytes)):
            print(f"{bcolors.OKGREEN}Successful export{bcolors.ENDC}")
    #if user entered erroneous input
    else:
        print(f"{bcolors.FAIL}ERROR: INVALID KEY TYPE{bcolors.ENDC}")

def generate_keys(my_keys):
    answer = input(f"{bcolors.WARNING}Are you sure you want to regenerate keys?\nAny public key sent will be invalid [y/Y/n/N]\n:{bcolors.ENDC}")
    if answer == "y" or answer == "Y":
        print("Generating new keys... please be patient")
        my_keys.GenKeys()
        print(f"{bcolors.OKGREEN}Keys have been regenerated{bcolors.ENDC}")
        print(f"{bcolors.WARNING}*Make sure to save keys or they will not be available next session*{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}Regeneration has been aborted{bcolors.ENDC}")

def start_session(server):
    ip = input("Please enter an IP address to connect to\n:").strip()
    port = input("Please enter the destination port to connect to\n:").strip()
    server.connect_client(ip_address=ip, port=port)
    pass

def view_session(server):
    pass

def clear_session(server):
    pass

def main():
    #import config file
    config = Config()
    #load in RSA key from files
    my_keys = RSA_Key(config, private_file=config.priv, public_file=config.pub)
    #start server side of p2p to accept incoming connections
    server = Server(my_keys)
    threading.Thread(target=server.start).start()
    time.sleep(1)
    #default value to act as do-while
    answer = '0'
    while(answer != '9'):
        #print the main meny
        print_menu(my_keys)
        #grab user input
        answer = input(":").strip()
        match answer:
            case "1": 
                #import keys
                import_keys(my_keys=my_keys)
            case "2": 
                #export keys
                export_keys(my_keys=my_keys)
            case "3": 
                #generate keys
                generate_keys(my_keys=my_keys)
            case "4":
                #start session
                start_session(server=server)
            case "5":
                #view session
                view_session(server=server)
            case "6":
                #clear session
                clear_session(server=server)
            case "9":
                #exit
                break
            case _:
                print(f"{bcolors.FAIL}INVALID OPTION{bcolors.ENDC}")
        input("press 'ENTER' to continue")
    """
    print("encrypting message hello world")
    encrypted_message = my_keys.EncryptMessage("How is your day going?")
    with open("test.txt", "wb") as test:
        [test.write(m) for m in encrypted_message]
    #print(my_keys.DecryptMessage(encrypted_message))
    with open("test.txt", "rb") as test:
        encrypted_message = [ test.read(x) for x in (512, 16, 16, 4, -1) ]
        decrypted_message = my_keys.DecryptMessage(encrypted_message)
    print(decrypted_message)
    """
    #disable the server from listening to more connections
    server.running = False
    #send sudo client to server to escape accept() hang
    server.connect_client(SERVER_IP, PORT)
    #sleep temporarily
    time.sleep(0.5)
    #every server that we have connected to should get a 
    #detatch message and should be detached from
    for connection in server.connections: 
        connection.sendall(MSG_DISS)
        connection.close()
    #close the server
    server.server.close

if __name__ == "__main__":
    main()
    

"""
write bytes to stream 
-------------------
with open("test.txt", "wb") as test:
    [test.write(m) for m in encrypted_message]


read bytes from stream 
--------------------
with open("test.txt", "rb") as test:
    encrypted_message = [ test.read(x) for x in (512, 16, 16, -1) ]
    decrypted_message = my_keys.DecryptMessage(encrypted_message)
"""