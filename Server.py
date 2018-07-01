import binascii
import json
import random
import socket
import sys

import phe.encoding
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_PSS
from Cryptodome.Random import random
from phe import paillier

def main():
    # create sockets
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    HOST = socket.gethostname()  # Symbolic name meaning all available interfaces
    PORT = 4321  # Arbitrary non-privileged port

    print('Socket created')

    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        print('Bind failed')
        sys.exit()

    print('Socket bind complete')

    s.listen(10)
    print('Socket now listening')
    dict = {}

    # say hello to Alice and Bob when they connect
    connAlice, addr = s.accept()
    print('Connected with ' + addr[0] + ':' + str(addr[1]))
    data = connAlice.recv(1024)
    if data.decode() == 'Alice':
        name = 'Alice'
        dict[addr] = 'Alice'
    else:
        print('Invalid client')
    reply = ('Hello' + name + '! ' + 'This is your connection: ' + addr[0] + ':' + str(addr[1]) + '. Please send me your encrypted secret.')

    connAlice.sendall(reply.encode())
    print('I said Hello to Alice')

    connBob, addr = s.accept()
    print('Connected with ' + addr[0] + ':' + str(addr[1]))
    data = connBob.recv(1024)
    if data.decode() == 'Bob':
        name = 'Bob'
        dict[addr] = 'Bob'
    else:
        print('Invalid client')
    reply = ('Hello' + name + '! ' + 'This is your connection: ' + addr[0] + ':' + str(addr[1]) + '. Please send me your encrypted secret.')
    connBob.sendall(reply.encode())
    print('I said Hello to Bob')

    #get homomorphic public key of Alice and Bob
    with open('homomorphic_key.txt') as json_file:
        data = json.load(json_file)
        public_key = paillier.PaillierPublicKey(n=int(data['public_key']))

    # receive Alice's encrypted secret
    AliceJSON = connAlice.recv(4096)
    received_dict = json.loads(AliceJSON)
    cipherAlice = paillier.EncryptedNumber(public_key, int(received_dict['cipher'][0]), int(received_dict['cipher'][1]))
    # receive Bob's encrypted secret
    BobJSON = connBob.recv(4096)
    received_dict = json.loads(BobJSON)
    cipherBob = paillier.EncryptedNumber(public_key, int(received_dict['cipher'][0]), int(received_dict['cipher'][1]))
    print('I have received Alice and Bob\'s secrets')

    # add them homomorphically
    minus = phe.encoding.EncodedNumber.encode(public_key, -1)
    cipherBob = minus * cipherBob
    added = cipherAlice + cipherBob
    # multiply it by a blinding factor so as to not leak any information
    blinding_factor = random.randint(1, 100000)
    encoded_blinding_factor = phe.encoding.EncodedNumber.encode(public_key, blinding_factor)
    added = added * encoded_blinding_factor
    added_secrets = {}
    # using the Server's public key, sign the answer that is to be sent back
    key = RSA.importKey(open("privkey.pem").read())
    h = SHA1.new()

    added_secrets['encrypted'] = str(added.ciphertext()), added.exponent
    h.update(str(added.ciphertext()).encode())
    h.update(str(added.exponent).encode())
    signer = PKCS1_PSS.new(key)
    signature = signer.sign(h)
    added_secrets['signature'] = binascii.hexlify(signature).decode('utf-8')
    answer = json.dumps(added_secrets).encode()
    # now send Alice and Bob the answer, they will decrypt it and find out if the secrets were equal
    try:
        # Set the whole string
        connAlice.sendall(answer)
        print('I have sent Alice the answer')
    except socket.error:
        # Send failed
        print('Send failed')
        sys.exit()
    try:
        # Set the whole string
        connBob.sendall(answer)
        print('I have sent Bob the answer')
    except socket.error:
        # Send failed
        print('Send failed')
        sys.exit()
# close all connections
    connAlice.close()
    connBob.close()
    s.close()


if __name__ =='__main__':
    main()