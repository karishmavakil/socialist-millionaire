# Socket client example in python

import binascii
import json
import socket  # for sockets
import sys  # for exit
from sys import argv
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_PSS
from phe import paillier


def main():
    name =argv[1]
    # read the homomorphic public and private keys shared by Alice and Bob
    with open('homomorphic_key.txt') as json_file:
        data = json.load(json_file)
        public_key = paillier.PaillierPublicKey(n=int(data['public_key']))
        private_key = paillier.PaillierPrivateKey(public_key, data['private_key'][0],data['private_key'][1])
    # create an INET, STREAMing socket

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print('Failed to create socket')
        sys.exit()

    print('Socket Created')

    host = socket.gethostname()
    port = 4321;

    try:
        remote_ip = socket.gethostbyname(host)

    except socket.gaierror:
        # could not resolve
        print('Hostname could not be resolved. Exiting')
        sys.exit()

    # Connect to remote server
    s.connect((remote_ip, port))

    print('Socket Connected to ' + host + ' on ip ' + remote_ip)
    # Saying hello to the server
    message = name

    try:
        # Set the whole string
        s.sendall(message.encode())
    except socket.error:
        # Send failed
        print('Send failed')
        sys.exit()

    print('Message sent successfully')

    # Now receive data
    reply = s.recv(4096)

    print(reply)

    # encrypt the secret message with the homomorphic public key
    secret_message = int(argv[2])
    cipher = public_key.encrypt(secret_message)
    secret = {}
    secret['cipher'] = (str(cipher.ciphertext()), cipher.exponent)
    serialised = json.dumps(secret).encode()

    try:
        # Set the whole string
        # print(serialised)
        s.sendall(serialised)
        print('I have sent the encrypted secret')
    except socket.error:
        # Send failed
        print('Send failed')
        sys.exit()

    # Now receive the answer back from the server
    reply = s.recv(4096)
    # print(reply)
    received_dict = json.loads(reply)
    answer = paillier.EncryptedNumber(public_key, int(received_dict['encrypted'][0]),
                                         int(received_dict['encrypted'][1]))

    # first check the signature, Alice has access to the verification key of the Server
    key = RSA.importKey(open("pubkey.pem").read())
    h = SHA1.new()
    h.update(received_dict['encrypted'][0].encode())
    h.update(str(received_dict['encrypted'][1]).encode())
    signature =binascii.unhexlify(received_dict['signature'].encode('utf-8'))
    verifier = PKCS1_PSS.new(key)
    if verifier.verify(h, signature):
        print("The signature is authentic.")
    else:
        print("The signature is not authentic.")
    # now decrypt the answer using private key, if it is 0 then strings were equal otherwise unequal

    key_decrypt = private_key.decrypt(answer)
    if key_decrypt==0:
        print("The strings were equal!")
    else:
        print("The strings were unequal!")

    # close connections
    s.close()


if __name__ =='__main__':
    main()