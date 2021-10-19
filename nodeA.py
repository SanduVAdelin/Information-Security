import socket
from KM import KM
import base64
from Crypto.Cipher import AES

HOST = '127.0.0.1'
#PORT -> initial nodeA este client pentru KM, serverul care trimite cheia nodului A
PORT = 65432
#PORT_B -> nodul A devine server pentru clientul B (nodul B). Astfel se asigura comunicarea dintre cele doua noduri
PORT_B = 54321
class node_A:

    #constructorul clasei node_A (atribute necesare ale nodului)
    def __init__(self, key_prime, IV) -> None:
        self.key_prime = key_prime
        self_key = 0
        self.decrypted_key = 0
        self.connection = 0
        self.communication_mode = ''
        self.IV = IV

    #Conectarea nodului la serverul KM pentru a primi cheia de la acesta
    def get_key(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as node_A_socket:
            node_A_socket.connect((HOST, PORT))
            node_A_socket.sendall(b'Conectarea cu key managerul pentru nodul A')
            self.key = node_A_socket.recv(1024)
            # print(self.key)

    #Functia care decripteaza cheia primita, utilizand key_prime, cheia publica cunoscuta de ambele noduri. Cheia decriptata va fi folosita in continuare pentru a cripta mesajul transmis nodului B
    def decrypt_key(self):
        decipher = AES.new(self.key_prime,AES.MODE_ECB)
        self.decrypted_key = decipher.decrypt(self.key)

    #Citim un fisier. Nodul A citeste mesajul transmis nodului B dintr-un fisier. Mesaj supus ulterior unei criptari.
    def read_from_file(self):
        with open('plaintext.txt', 'r') as file:
            message = file.read()
        return message

    #Deschiderea comunicarii cu nodul B. Nodul A transmite clientului sau cheia de criptare
    def send_key_to_node_B(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as node_A_socket:
            node_A_socket.bind((HOST, PORT_B))
            node_A_socket.listen()
            self.connection, addr = node_A_socket.accept()
            # print('Incepe comunicarea cu nodul B')    
            self.send_message_to_B(self.key)
    
    #Functia prin care nodul A transmite nodului cu care comunica modul de criptare al textului.
    def send_communication_mode(self, communication_mode):
        self.communication_mode = communication_mode.encode()
        self.send_message_to_B(self.communication_mode)
      
    #Functie prin care ne asiguram transmiterea corecta a informatiei. (OBS : initial trebuie sa transmitem lungimea mesajului transmis, vor exista probleme in cazul in care dorim sa transmitem un mesaj, dar cu o lungime necunoscuta. Buffer-ul canalului de comunicare nu se poate actuliza singur, nu cel putin in modul actual de comunicare)
    def send_message_to_B(self, message_to_send):
        length = str(len(message_to_send))
        while len(length) < 4:
            length += ' ' #lungimea mesajului fiind transmisa in bytes, acesta trebuie pus pe 4 posiztii pentru a fi encodat corect
        self.connection.sendall(length.encode())
        self.connection.sendall(message_to_send)

    #Functia care cripteaza un mesaj utilizand modul ECB al criptosistemului AES
    def encrypt_blocks_using_ECB(self, message):
        
        #impartim plaintextul in blocuri de cate 16 bytes, avand blocuri de lungimea cheii (128 biti)
        text_blocks = [message[i:i+16] for i in range(0, len(message), 16)]
        for i in range(1,17-len(text_blocks[-1])):
            text_blocks[-1] += ' ' #ultimului bloc i se adauga caractere suplimentare pentru a ajunge la dimensiunea ceruta

        cipher_blocks = [] #lista cu blocurile criptate

        # for text_block in text_blocks:
        #     print(text_block.encode())

        # print('Incriptarea folosind ECB')

        cipher = AES.new(self.decrypted_key, AES.MODE_ECB)
        #criptarea fiecarui bloc in parte si adaugarea acestuia in lista de transmis
        for block in text_blocks:
            encode_block = block.encode()
            cipher_blocks.append(cipher.encrypt(encode_block))
        
        return cipher_blocks

    #Functia de criptarea utilizand criptosistemul AES in modul de operare CFB
    def encrypt_blocks_using_CFB(self, message):

        #impartirea mesajului in blocuri de cate 16 bytes 
        text_blocks = [message[i:i+16] for i in range(0, len(message), 16)]
        for i in range(1,17-len(text_blocks[-1])):
            text_blocks[-1] += ' '

        cipher_blocks = []
        cipher = AES.new(self.decrypted_key, AES.MODE_ECB)
        ant_cipher = self.IV #se retine anteriorul criptat (acest mod de operare functioneaza ca un blockchain, fiecare bloc criptat depinde de criptarea unui bloc anterior)

        #criptarea efectiva a blocurilor de mesaj
        for block in text_blocks:
            encode_block = block.encode()
            ant_cipher_encrypted = cipher.encrypt(ant_cipher)
            cipher_blocks.append(bytes([_a ^ _b for _a, _b in zip(encode_block, ant_cipher_encrypted)]))
            ant_cipher = cipher_blocks[-1]
        
        return cipher_blocks
        
    #Functia prin care transmitem blocurile criptate nodului B
    def send_cipher_blocks_to_node_B(self, cipher_blocks : list):
        #transmitem initial numarul de blocuri criptate pentru a sti de cate ori avem nevoie sa facem 'receive' in client
        count = 0
        for element in cipher_blocks:
            count +=1
    
        self.send_message_to_B(str(count).encode())
        for cipher_block in cipher_blocks:
            self.send_message_to_B(cipher_block) #transmitem mesajul criptat (sub forma de blocuri criptate)
            

if __name__ == "__main__":
    
    #key_prime si IV sunt cunoscute de ambele noduri (variabile constante generate in mod aleator in urma efectarii unor teste)
    key_prime = b'\\qW\x0b\xb2F\xda\xb0\x04\xf23$\x92\x85\x12\xac'
    IV = b'\xfb*r\x1c\x9d\x18\xee\xe90\xe7\x07\xafq\x1a\x0c\x03'

    A_node = node_A(key_prime,IV) #crearea unui nod
    A_node.get_key()
    A_node.send_key_to_node_B()
    A_node.decrypt_key()
    
    # print(f'Cheia descripata este : {A_node.decrypted_key}')
    # print('Incepem comunicarea')
    communication_mode = input('''Selecteaza modul de operare al criptosistemului : 
    1. ECB
    2. CFB \n''')

    A_node.send_communication_mode(communication_mode)

    if communication_mode == 'ECB':
         cipher_blocks_for_ECB = A_node.encrypt_blocks_using_ECB(A_node.read_from_file())
         A_node.send_cipher_blocks_to_node_B(cipher_blocks_for_ECB)
    elif communication_mode == 'CFB':
         cipher_blocks_for_CFB = A_node.encrypt_blocks_using_CFB(A_node.read_from_file())
         A_node.send_cipher_blocks_to_node_B(cipher_blocks_for_CFB)

    
