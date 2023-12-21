from Colors import Colors
#Crypto Libraries
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA512
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes
import getpass

#CRYPTO FINALS
RSA_BITS = 4096
HASH_ALGO = SHA512
AES_BITS = 256
CIPHER_MODE = AES.MODE_GCM
PKI_FILE_FORMAT = "PEM"
MAX_MESSAGE_LEN = 500
HEADER = 4
FORMAT = "utf-8"

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
            print(f"{Colors.FAIL}Too many paramaters for public key passed. Only pass a file or a string{Colors.ENDC}")
        if private_bytes and private_file:
            print(f"{Colors.FAIL}Too many paramaters for private key passed. Only pass a file or a string{Colors.ENDC}")
        
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
    def ExportKey(self, file:str, key:str) -> bool | None:
        pass1 = None
        pem = b""
        if(key.has_private()):
            #get password to encrypt the PEM file
            print(f"{Colors.WARNING}You are exporting a private key, please provide \na secure password to protect your private key{Colors.ENDC}")
            pass1 = getpass.getpass("Enter password for private key  : ")
            pass2 = getpass.getpass("Confirm password for private key: ")
            if(pass1 != pass2):
                print(f"{Colors.FAIL}ERROR: PASSWORDS DO NOT MATCH (keys were not generated){Colors.ENDC}")
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
            print(f"{Colors.FAIL}ERROR: OPENING OR WRITTING TO PEM FILE{Colors.ENDC}")
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
    def ImportKey(self, file:str, *, is_private:bool=False) -> bool | None: 
        
        try:
            with open(file, "r") as pem_file:
                #get password if private key
                pass1=None
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
            print(f"{Colors.FAIL}ERROR: INCORRECT PASSWORD{Colors.ENDC}")   
        except Exception as e:
            print(f"{Colors.FAIL}ERROR: KEY NOT READ FROM FILE '{file}'{Colors.ENDC}")
        return None
    
    """
        Function Encrypt Message
        ========================
        Encrypts the message using the class' public key
        param: message to be encrypted
        returns: string representing the cipher text
    """
    def EncryptMessage(self, message:str, public_bytes:str, override:bool=False) -> tuple[bytes, bytes, bytes, bytes, bytes] | None:
        #make sure message length is short enough to be sent in one message
        if(not override and len(message) > MAX_MESSAGE_LEN):
            print(f"{Colors.FAIL}ERROR: MESSAGE IS TOO LONG, PLEASE SHORTEN TO LESS THAN {MAX_MESSAGE_LEN:,} CHARACTERS{Colors.ENDC}")
            input("PRESS ENTER TO CONTINUE")
            return None
        #generate session key
        session_key = get_random_bytes(AES_BITS//8)

        if(public_bytes is None):
            print(f"{Colors.FAIL}ERROR: TRYING TO ENCRYPT WITH NULL KEY{Colors.ENDC}")
            return None
        
        #encrypt session key using asymetric encryption (public key)
        try:
            cipher_rsa = PKCS1_OAEP.new(key=public_bytes, hashAlgo=HASH_ALGO)
            enc_session_key = cipher_rsa.encrypt(session_key)
        except Exception:
            print(f"{Colors.FAIL}ERROR: RSA ENCRYPTION{Colors.ENDC}")
            return None
        
        #use AES and session_key to encrypt message
        try:
            cipher_aes = AES.new(session_key, CIPHER_MODE)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode(FORMAT))
        except Exception:
            print(f"{Colors.FAIL}ERROR: AES ENCRYPTION{Colors.ENDC}")
            return None
        #print(f"ENCRYPT:\n>%x\n>%x\n>%x\n>%x\n", enc_session_key, cipher_aes.nonce, tag, len(ciphertext).to_bytes(HEADER,'big'), ciphertext)

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
        ciphertext = ciphertext[3]

        #print(f"DECRYPT:\n>%x\n>%x\n>%x\n>%x\n", enc_session_key, nonce, tag, len(ciphertext).to_bytes(HEADER,'big'), ciphertext)
        #check if key is not NULL
        if(self.private_bytes is None):
            print(f"{Colors.FAIL}ERROR: ATTEMPTING DECRYPTION WITH NULL KEY{Colors.ENDC}")
            return None
        
        # Decrypt the session key with the private RSA key
        try:
            cipher_rsa = PKCS1_OAEP.new(self.private_bytes, hashAlgo=HASH_ALGO)
            session_key = cipher_rsa.decrypt(enc_session_key)
        except Exception:
            print(f"{Colors.FAIL}ERROR: RSA DECRYPTION{Colors.ENDC}")
            return None
        
        # Decrypt the data with the AES session key
        try:
            cipher_aes = AES.new(session_key, CIPHER_MODE, nonce)
            message = cipher_aes.decrypt_and_verify(ciphertext, tag)
        except Exception:
            print(f"{Colors.FAIL}ERROR: AES DECRYPTION{Colors.ENDC}")
            return None
        