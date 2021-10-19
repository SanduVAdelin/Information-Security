from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import os
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
import secrets
from simple_aes_cipher import AESCipher
import socket

#KM este server pentru nodul A pentru a-i comunica acestuia cheia de criptare
HOST = '127.0.0.1'
PORT = 65432
class KM:
    def __init__(self, block_size, key_prime):
        self.key_prime = key_prime
        self.block_size = block_size

    def generate_key(self):
        secret_key = secrets.token_bytes(self.block_size)
        cipher_for_key = AES.new(self.key_prime, AES.MODE_ECB) #criptam cheia secreta generata random utilizand cheia publica k'
        cipher_key = cipher_for_key.encrypt(secret_key)
        return cipher_key
    
    #Conexiunea cu nodul A pentru a-i trimite cheia
    def send_key_to_node_A(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as km_socket:
            km_socket.bind((HOST, PORT))
            km_socket.listen()
            connection_A, addr = km_socket.accept()

            print('Incepe comunicarea cu nodul A pentru transmiterea cheii')

            connection_A.recv(1024)
            key = self.generate_key()
            connection_A.sendall(key)




if __name__ == "__main__":

    key_prime = b'\\qW\x0b\xb2F\xda\xb0\x04\xf23$\x92\x85\x12\xac'
    key_manager = KM(16,key_prime)
    key_manager.send_key_to_node_A()
