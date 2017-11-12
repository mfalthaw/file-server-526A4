import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class Protocol:
    AES128 = 'aes128'
    AES256 = 'aes256'
    NULL = 'null'
    LENGTH_128 = 16
    LENGTH_256 = 32
    __DEBUG = True

    CIPHERS = [
        AES128,
        AES256,
        NULL,
    ]

    __INITIALIZATION_VECTOR = 'IV'
    __SESSION_KEY = 'SK'
    __BUFFER_SIZE = 1024

    # ACK Types
    OK_ACK = 'OK'
    BAD_KEY_ACK = 'BAD_KEY'

    '''
    Instance Methods
    '''

    def __init__(self, sock, secret):
        self.socket = sock
        self.secret = secret
        self.session_key = None
        self.init_vector = None
        self.send_message = None
        self.send_data = None
        self.receive_message = None
        self.receive_data = None

    def init_utils(self, cipher_type, nonce):
        ''' Initialize various utilities used by class '''
        if cipher_type != Protocol.NULL:
            self.session_key = Protocol.__session_key(self.secret, nonce, cipher_type)
            self.init_vector = Protocol.__init_vector(self.secret, nonce)
        self.send_message = lambda msg: Protocol.__send_message(self.socket, msg, cipher_type, self.session_key, nonce)
        self.send_data = lambda data: Protocol.__send_data(self.socket, data, cipher_type, self.session_key, self.init_vector)
        self.receive_data = lambda: Protocol.__receive_data(self.socket, cipher_type, self.session_key, self.init_vector)
        self.receive_message = lambda: Protocol.__receive_message(self.socket, cipher_type, self.session_key, self.init_vector)


    def send_plain_message(self, msg):
        ''' Send a plaintext message '''
        Protocol.__send_message(self.socket, msg, Protocol.NULL)

    def get_plain_message(self):
        ''' Receive plain text message '''
        return Protocol.__receive_message(self.socket, Protocol.NULL)

    def rec_ack(self):
        ''' Receieve an ACK '''
        ack = self.receive_message()
        if ack == Protocol.OK_ACK:
            return

        else:
            raise NotImplementedError('no such ack type: {}'.format(ack))

    def send_ack(self, ack_type):
        ''' Send an ACK '''
        self.send_message(ack_type)

    def challenge(self):
        ''' build the challenge '''
        m = hashlib.sha256()
        m.update(self.secret.encode('utf-8'))
        return str(m.hexdigest())


    '''
    Static Methods
    '''

    @staticmethod
    def log(msg):
        ''' Log a debug message '''
        if Protocol.__DEBUG:
            print(msg)

    @staticmethod
    def __init_vector(key, nonce):
        ''' Create the initialization vector '''
        return Protocol.__sha256_key(
            key,
            nonce,
            Protocol.__INITIALIZATION_VECTOR,
            Protocol.LENGTH_128
        )

    @staticmethod
    def __session_key(key, nonce, cipher_type):
        ''' Create the session key '''
        if cipher_type == Protocol.NULL:
            return ''
        elif cipher_type == Protocol.AES128:
            length = Protocol.LENGTH_128
        elif cipher_type == Protocol.AES256:
            length = Protocol.LENGTH_256

        return Protocol.__sha256_key(key, nonce, Protocol.__SESSION_KEY, length)

    @staticmethod
    def __send_message(socket, msg, cipher_type, session_key=None, nonce=None):
        ''' Send a message through a socket '''
        Protocol.log('Sending message: {}'.format(msg))
        data = msg.encode('utf-8')
        Protocol.__send_data(socket, data, cipher_type, session_key, nonce)

    @staticmethod
    def __send_data(socket, data, cipher_type, session_key=None, init_vector=None):
        ''' Send data through a socket '''
        Protocol.__validate_messenger(cipher_type, session_key, init_vector)

        if len(data) > Protocol.__BUFFER_SIZE:
            raise ValueError('Attempting to send too much data')

        socket.send(Protocol.__encrypt(data, cipher_type, session_key, init_vector))

    @staticmethod
    def __receive_data(socket, cipher_type, session_key=None, init_vector=None):
        ''' Receive data through a socket '''
        Protocol.__validate_messenger(cipher_type, session_key, init_vector)
        while True:
            ct = socket.recv(Protocol.__BUFFER_SIZE)
            if not ct:
                continue
            msg = Protocol.__decrypt(ct, cipher_type, session_key, init_vector).decode('utf-8')
            if not msg  or msg == 'None':
                continue

            break
        return msg

    @staticmethod
    def __receive_message(socket, cipher_type, session_key=None, init_vector=None):
        ''' Receive a message '''
        Protocol.__validate_messenger(cipher_type, session_key, init_vector)
        while True:
            ct = socket.recv(Protocol.__BUFFER_SIZE)
            if not ct:
                continue
            msg = Protocol.__decrypt(ct, cipher_type, session_key, init_vector).decode('utf-8')
            if not msg  or msg == 'None':
                continue

            break
        Protocol.log('Message received: {}'.format(msg))
        return str(msg)


    @staticmethod
    def __validate_messenger(cipher_type, session_key, init_vector):
        ''' Validate args to send/receive '''
        if cipher_type not in Protocol.CIPHERS:
            raise ValueError('No such cipher: {}'.format(cipher_type))

        if cipher_type != Protocol.NULL and (not session_key or not init_vector):
            raise ValueError('secret and nonce must be defined')

    @staticmethod
    def __sha256_key(secret, nonce, key_type, length):
        ''' Key gen utility using sha256 '''
        m = hashlib.sha256()
        m.update(secret.encode('utf-8'))
        m.update(nonce.encode('utf-8'))
        m.update(key_type.encode('utf-8'))
        return m.digest()[:length]

    @staticmethod
    def __encrypt(data, cipher_type, session_key, init_vector):
        ''' Encryption utliity '''
        if cipher_type == Protocol.NULL:
            return data

        cipher = Protocol.__create_cipher(session_key, init_vector)
        encryptor = cipher.encryptor()

        return encryptor.update(data) + encryptor.finalize()

    @staticmethod
    def __decrypt(payload, cipher_type, session_key, init_vector):
        ''' Decryption utility '''
        if cipher_type == Protocol.NULL:
            return payload

        cipher = Protocol.__create_cipher(session_key, init_vector)
        decryptor = cipher.decryptor()

        return decryptor.update(payload) + decryptor.finalize()

    @staticmethod
    def __create_cipher(session_key, init_vector):
        ''' Create encryptor '''
        algorithm = algorithms.AES(session_key)
        mode = modes.CBC(init_vector)
        backend = default_backend()
        return Cipher(algorithm, mode, backend=backend)
