#My libraries
from RSA import RSA_Key
from Colors import Colors
from Server import Server
import Screen

#other libraries
import time
from threading import Thread, active_count#,Lock
import ipaddress

#Server Constants
PORT = 4445 #port to run the server on
SERVER_IP = "127.0.0.1"
#TODO REMOVE THIS LATER!!!
MSG_DISS = b"[DISCONNECT]"   #message to safely disconnect from server
#MSG_CONN = "[CONNECT]"

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
    Function Print Menu
    ====================
    Prints out the main menu of the basic user interface
    param: the keys of the user
    returns: None
"""
def print_menu(my_keys:RSA_Key) -> None:
    has_pub = not my_keys.public_bytes is None
    has_priv = not my_keys.private_bytes is None
    Screen.print_menu(has_pub=has_pub, has_priv=has_priv, IP=SERVER_IP, PORT=PORT)

def import_keys(my_keys):
    #get parameters for importing keys from user
    file_name = input("What is the name of the PEM file you wish to import?\n:").strip()
    is_priv = input("Is this a private key? [y/Y/n/N]\n:").strip()
    #convert str var into boolean var
    is_priv = is_priv == "y" or is_priv == "Y" 
    #import keys into system
    if(my_keys.ImportKey(file_name, is_private=is_priv)):
        print(f"{Colors.OKGREEN}Successful import!{Colors.ENDC}")

def export_keys(my_keys:RSA_Key):
    #get parameters for exporting keys from user
    file_name = input("What is the name of the pem file you wish to export to?\n:")
    key_type = input("Do you wish to export the public or private key? [public/private]\n:")
    #check if public or private key and then export
    if key_type == "public":
        if(my_keys.ExportKey(file_name, my_keys.public_bytes)):
            print(f"{Colors.OKGREEN}Successful export{Colors.ENDC}")
    elif key_type == "private":
        if(my_keys.ExportKey(file_name, my_keys.private_bytes)):
            print(f"{Colors.OKGREEN}Successful export{Colors.ENDC}")
    #if user entered erroneous input
    else:
        print(f"{Colors.FAIL}ERROR: INVALID KEY TYPE{Colors.ENDC}")

def generate_keys(my_keys:RSA_Key):
    answer = input(f"{Colors.WARNING}Are you sure you want to regenerate keys?\nAny public key sent will be invalid [y/Y/n/N]\n:{Colors.ENDC}")
    if answer == "y" or answer == "Y":
        print("Generating new keys... please be patient")
        my_keys.GenKeys()
        print(f"{Colors.OKGREEN}Keys have been regenerated{Colors.ENDC}")
        print(f"{Colors.WARNING}*Make sure to save keys or they will not be available next session*{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}REGENERATION HAS BEEN ABORTED{Colors.ENDC}")

def start_session(server:Server):
    ip = input("Please enter an IP address to connect to\n:").strip()
    port = input("Please enter the destination port to connect to\n:").strip()
    if(not server.connect_to_client(ip_address=ip, port=port)):
        return
    print(f"{Colors.OKGREEN}SESSION SUCCESSFULLY STARTED{Colors.ENDC}")
    time.sleep(0.1)
    name = input("If you would like to assign a contact name with this address, please enter it in\n:").strip()
    if name:
        validation = input(f"Are you sure you want to assign {name} to {ip}:{port}? [y/n]\n:").strip()
        if validation != "y" and validation != "Y":
            name = None
    if name:
        server.contacts.update({name:(ip,int(port))})

def view_sessions(server:Server):
    server.get_connections()

def clear_session(server:Server):
    pass

def view_messages(server:Server):
    view_sessions(server=server)
    contact = input("Which contact would you like to view?\n:")
    try: 
        contact = int(contact)
    except ValueError:
        print(f"{Colors.FAIL}PLEASE ENTER A NUMBER BETWEEN 1-{len(server.clients)}{Colors.ENDC}")
        return None
    if contact < 0 or contact > len(server.clients):
        print(f"{Colors.FAIL}PLEASE ENTER A NUMBER BETWEEN 1-{len(server.clients)}{Colors.ENDC}")
        return None
    
    for message in server.messages.get(server.clients[contact-1]):
        if message[0] == (SERVER_IP,PORT):
            print('\t',end="")
        print(message[1])

def send_message(server:Server):
    #get IP address or contact name of message recipient
    view_sessions(server=server)
    dest = input("Who would you like to send a message to?\n[IPv4 address or contact name]\n:").strip()
    #store ip,port tuple for server use
    addr = None
    #if null entry throw error
    if not dest:
        print(f"{Colors.FAIL}ERROR: INVALID INPUT{Colors.ENDC}")
        return
    try:
        #first search contact liest
        if server.contacts.get(dest):
            print(server.contacts.get(dest))
            #if contact found, use dict to get addr value
            addr = server.contacts.get(dest)
        #check if entry is a valid format for IPv4 address
        elif ipaddress.ip_address(dest):
            #if valid IP address format ask for port
            port = input(f"Please enter the port for '{dest}'\n:").strip()
            #make tuple of ip and port
            addr = (dest, int(port))
            #check if addr is a valid addr in keychain
            if not server.keychain.get(addr):
                raise ValueError
        else:
            raise ValueError
    except ValueError:
        print(f"{Colors.FAIL}ERROR: MALFORMED IP ADDRRESS OR UNKNOWN CONTACT '{dest}'{Colors.ENDC}")
        return None
    #if valid recipient has been confirmed, ask for message
    message = input("What message would you like to send?\n:")
    #pass addr and message to server to be sent out
    if server.send_message(addr, message):
        server.messages.get(addr).append( ((SERVER_IP,PORT),message) )

def main():
    #import config file
    config = Config()
    #load in RSA key from files
    my_keys = RSA_Key(config, private_file=config.priv, public_file=config.pub)
    #start server side of p2p to accept incoming connections
    server = Server(my_keys)
    Thread(target=server.start).start()
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
                view_sessions(server=server)
            case "6":
                #clear session
                clear_session(server=server)
            case "7":
                view_messages(server=server)
            case "8":
                send_message(server=server)
            case "9":
                #exit
                break
            case _:
                print(f"{Colors.FAIL}ERROR: INVALID OPTION{Colors.ENDC}")
        input("press 'ENTER' to continue")
    
    #disable the server from listening to more connections
    server.running = False
    #send sudo client to server to escape accept() hang
    server.connect_to_client(SERVER_IP, PORT)
    #every server that we have connected to should get a 
    #detatch message and should be detached from
    for client in server.clients:
        connection = server.keychain.get(client)[0]
        connection.send(MSG_DISS)
        connection.close()
    #close the server
    server.server.close()

if __name__ == "__main__":
    main()