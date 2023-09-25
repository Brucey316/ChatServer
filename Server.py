from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA512
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes
import getpass

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
        self.private_bytes = RSA.generate(bits=4096)
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
            pem = key.export_key(format='PEM', passphrase=pass1, pkcs=8)
        else:
            pem = key.export_key(format='PEM')
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
        if(is_private):
            #get password if private key
            pass1 = getpass.getpass("Enter password for private key: ")
        try:
            with open(file, "r") as pem_file:
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
        #generate session key
        session_key = get_random_bytes(32)

        if(self.public_bytes is None):
            print(f"{bcolors.FAIL}ERROR: TRYING TO ENCRYPT WITH NULL KEY{bcolors.ENDC}")
            return None
        
        #encrypt session key using asymetric encryption (public key)
        try:
            cipher_rsa = PKCS1_OAEP.new(self.public_bytes, hashAlgo=SHA512)
            enc_session_key = cipher_rsa.encrypt(session_key)
        except Exception:
            print(f"{bcolors.FAIL}ERROR: RSA ENCRYPTION{bcolors.ENDC}")
            return None
        
        #use AES and session_key to encrypt message
        try:
            cipher_aes = AES.new(session_key, AES.MODE_GCM)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode("utf-8"))
        except Exception:
            print(f"{bcolors.FAIL}ERROR: AES ENCRYPTION{bcolors.ENDC}")
            return None
        
        return (enc_session_key, cipher_aes.nonce, tag, ciphertext)
    
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
        ciphertext = ciphertext[3]

        #check if key is not NULL
        if(self.private_bytes is None):
            print(f"{bcolors.FAIL}ERROR: ATTEMPTING DECRYPTION WITH NULL KEY{bcolors.ENDC}")
            return None
        
        # Decrypt the session key with the private RSA key
        try:
            cipher_rsa = PKCS1_OAEP.new(self.private_bytes, hashAlgo=SHA512)
            session_key = cipher_rsa.decrypt(enc_session_key)
        except Exception:
            print(f"{bcolors.FAIL}ERROR: RSA DECRYPTION{bcolors.ENDC}")
            return None
        
        # Decrypt the data with the AES session key
        try:
            cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
            message = cipher_aes.decrypt_and_verify(ciphertext, tag)
        except Exception:
            print(f"{bcolors.FAIL}ERROR: AES DECRYPTION{bcolors.ENDC}")
            return None
        
        return message.decode("utf-8")
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

def main():
    config = Config()
    my_keys = RSA_Key(config, private_file=config.priv, public_file=config.pub)
    answer = '0'
    while(answer != '9'):
        print_menu(my_keys)
        answer = input(":").strip()
        print(answer)
        match answer:
            case "1": #import keys
                #get parameters for importing keys from user
                file_name = input("What is the name of the pem file you wish to import?\n:").strip()
                is_priv = input("Is this a private key? [y/Y/n/N]\n:").strip()
                #convert str var into boolean var
                is_priv = is_priv == "y" or is_priv == "Y" 
                #import keys into system
                if(my_keys.ImportKey(file_name, is_private=is_priv)):
                    print(f"{bcolors.OKGREEN}Successful import!{bcolors.ENDC}")
                input("press 'ENTER' to continue")

            case "2": #export keys
                #get parameters for exporting keys from user
                file_name = input("What is the name of the pem file you wish to export to?\n:").strip()
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
                input("press 'ENTER' to continue")

            case "3": #generate keys
                answer = input(f"{bcolors.WARNING}Are you sure you want to regenerate keys?\nAny public key sent will be invalid [y/Y/n/N]\n:{bcolors.ENDC}")
                if answer == "y" or answer == "Y":
                    print("Generating new keys... please be patient")
                    my_keys.GenKeys()
                    print(f"{bcolors.OKGREEN}Keys have been regenerated{bcolors.ENDC}")
                    print(f"{bcolors.WARNING}*Make sure to save keys or they will not be available next session*{bcolors.ENDC}")
                else:
                    print(f"{bcolors.FAIL}Regeneration has been aborted{bcolors.ENDC}")
                
                input("press 'ENTER' to continue")

            case "4":
                #start session
                pass

            case "5":
                #view session
                pass

            case "6":
                #clear session
                pass

            case "9":
                pass

            case _:
                print(f"{bcolors.FAIL}INVALID OPTION{bcolors.ENDC}")

    print("encrypting message hello world")
    encrypted_message = my_keys.EncryptMessage("How is your day going?")
    with open("test.txt", "wb") as test:
        [test.write(m) for m in encrypted_message]
    #print(my_keys.DecryptMessage(encrypted_message))
    with open("test.txt", "rb") as test:
        encrypted_message = [ test.read(x) for x in (512, 16, 16, -1) ]
        decrypted_message = my_keys.DecryptMessage(encrypted_message)
    print(decrypted_message)
    

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