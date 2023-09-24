from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA512
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Random import get_random_bytes
import getpass

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
            self.dir = config.readline().split("=")[1].strip()
            self.keychain = config.readline().split("=")[1].strip()

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

    def __init__(self, config, public_file=None, private_file=None, public_bytes=None, private_bytes=None):
        #initialize values
        self.public_bytes = None
        self.private_bytes = None

        #check arguements passed (can't pass in file location and byte representation for same key type due to overwrites)
        if public_bytes and public_file:
            print("Too many paramaters for public key passed. Only pass a file or a string")
        if private_bytes and private_file:
            print("Too many paramaters for private key passed. Only pass a file or a string")
        
        #If key bytes are passed in, set as key value
        if public_bytes:
            self.public_bytes = public_bytes
        if private_bytes:
            self.private_bytes = private_bytes

        #Import keys from file
        if public_file:
            self.public_bytes = self.ImportKey(public_file)
        if private_file:
            self.private_bytes = self.ImportKey(private_file)
    
    """
        Function Gen Keys
        ================
        Generates new RSA keys and returns the byte representation
        parameters: None
        return:     public key, private key
    """
    def GenKeys(self):
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
    def ExportKey(self, file, key):
        try:
            with open(file, "wb") as pem_file:
                pem = key.export_key(format='PEM')
                pem_file.write(pem)
        except Exception as e:
            print("Error writing key to file")
            return None
        return True
    
    """
        Function Import Key
        ===================
        Import key from file and return the byte string
        param: file to read from
        returns: byte string (None if there is an error)
    """
    def ImportKey(self, file):
        try:
            with open(file, "r") as pem_file:
                return RSA.import_key(pem_file.read())
        except Exception as e:
            print("Error reading key from file")
            return None
        return None
    """
        Function Encrypt Message
        ========================
        Encrypts the message using the class' public key
        param: message to be encrypted
        returns: string representing the cipher text
    """
    def EncryptMessage(self, message):
        #generate session key
        session_key = get_random_bytes(32)
        #encrypt session key using asymetric encryption (public key)
        cipher_rsa = PKCS1_OAEP.new(self.public_bytes, hashAlgo=SHA512)
        enc_session_key = cipher_rsa.encrypt(session_key)
        #use AES and session_key to encrypt message
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode("utf-8"))
        return (enc_session_key, cipher_aes.nonce, tag, ciphertext)
    """
        Function Decrypt Message
        ========================
        Decrypts the message using the class' private key
        param: ciphertext to be decrypted
        returns: string representing the message
    """
    def DecryptMessage(self, ciphertext):
        enc_session_key = ciphertext[0]
        nonce = ciphertext[1]
        tag = ciphertext[2]
        ciphertext = ciphertext[3]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(self.private_bytes, hashAlgo=SHA512)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data.decode("utf-8")

def main():
    config = Config()
    my_keys = RSA_Key(config, private_file="my_priv.pem", public_file="my_pub.pem")
    #my_keys = RSA_Key(config)
    #my_keys.GenKeys()
    #my_keys.ExportKey(config.dir + "my_pub.pem", my_keys.public_bytes)
    #my_keys.ExportKey(config.dir + "my_priv.pem", my_keys.private_bytes)
    print("encrypting message hello world")
    #encrypted_message = my_keys.EncryptMessage("Hello World")
    
    

if __name__ == "__main__":
    main()

"""
write bytes to file 
-------------------
with open("test.txt", "wb") as test:
    [test.write(m) for m in encrypted_message]


read bytes from file 
--------------------
with open("test.txt", "rb") as test:
    encrypted_message = [ test.read(x) for x in (512, 16, 16, -1) ]
    decrypted_message = my_keys.DecryptMessage(encrypted_message)
"""