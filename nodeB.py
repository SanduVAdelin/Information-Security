import base64
from KM import KM
from nodeA import node_A
from Crypto.Cipher import AES
import socket

HOST = '127.0.0.1'
PORT_B = 54321
#Detalii pentru conectarea nodului B la serverul cu care comunica (nodul A)

class node_B:
    #atributele necesare nodului B. Acestea sunt initializate in constructor
    def __init__(self, key_prime, IV) -> None:
        self.key_prime = key_prime
        self.IV = IV
        self.decrypted_key = 0
        self.b_socket = 0
        self.key = 0
        self.communication_mode = ''
        self.cipher_blocks = []
        

    #Functia prin care decriptam cheia primita de la nodul A
    def decrypt_key(self):
        decipher = AES.new(self.key_prime,AES.MODE_ECB)
        self.decrypted_key = decipher.decrypt(self.key)
    
    #Functia prin care deschidem conexiunea cu nodul A si primim cheia de la acesta (cheia criptata, primita de A de la KM)
    def get_key(self):
            self.b_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.b_socket.connect((HOST, PORT_B))
            
            self.key = self.receive_from_node_A()
            # print(f'Cheia primita de la nodul A este : {self.key}')

    #Modul in care primim modalitatea de comunicare
    def get_communication_mode(self):
        self.communication_mode = self.receive_from_node_A()

    #Functia care asigura primirea mesajului corect de la nodul A (pereche cu functia send_message_to_node_B din clasa node_A)
    def receive_from_node_A(self):
        length = int(self.b_socket.recv(4).decode())
        return self.b_socket.recv(length) #returnam efectiv mesajul primit, stiind dimensiunea exacta a acestuia. Evitam problema cu bufferul

    #Primirea mesajului criptat de la nodul A
    def get_cipher_blocks_from_A(self):
        something = self.receive_from_node_A()
        for element in range(0,int(something)):
            self.cipher_blocks.append(self.receive_from_node_A())

        # print('Blocurile primite pentru decriptare sunt :')
        # print(self.cipher_blocks)

    #Decriptarea mesajului folosind modul de operare ECB
    def decrypt_blocks_using_ECB(self):
        decipher = AES.new(self.decrypted_key, AES.MODE_ECB)
        decipher_blocks = []
        for block in self.cipher_blocks:
            decipher_blocks.append(decipher.decrypt(block))
       
        #construirea efectiva a mesajului sub forma unui string, asa cum se gaseste acesta in fisierul din care citim
        # print(decipher_blocks)
        decipher_text = ''
        for block in decipher_blocks:
            decipher_text += block.decode()
        return decipher_text

    #Decriptarea mesajului folosind modul de operare CFB a criptosistemului AES
    def decrypt_blocks_using_CFB(self):
        decipher = AES.new(self.decrypted_key,AES.MODE_ECB)
        cipher = AES.new(self.decrypted_key,AES.MODE_ECB)
       
        ant_decipher = self.IV
        decipher_blocks = []
        for cipher_block in self.cipher_blocks:
            ant_decipher_encrypt = cipher.encrypt(ant_decipher)
            decipher_blocks.append(bytes([_a ^ _b for _a, _b in zip(ant_decipher_encrypt, cipher_block)]))
            ant_decipher = cipher_block
        
        decipher_text = ''
        for block in decipher_blocks:
            decipher_text += block.decode()
        return decipher_text


if __name__ == "__main__":
    
    key_prime = b'\\qW\x0b\xb2F\xda\xb0\x04\xf23$\x92\x85\x12\xac'
    IV = b'\xfb*r\x1c\x9d\x18\xee\xe90\xe7\x07\xafq\x1a\x0c\x03'

    B_node = node_B(key_prime, IV)
    B_node.get_key()
    B_node.decrypt_key()
    
    B_node.get_communication_mode()
    print(f'Modul de comunicare transmis este : {B_node.communication_mode.decode()}')

    if B_node.communication_mode.decode() == 'ECB':
       B_node.get_cipher_blocks_from_A()
       print(B_node.decrypt_blocks_using_ECB())
    elif B_node.communication_mode.decode() == 'CFB':
        B_node.get_cipher_blocks_from_A()
        print(B_node.decrypt_blocks_using_CFB())
    
#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