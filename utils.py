import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


class Utils:
    AES128 = 'aes128'
    AES256 = 'aes256'
    NULL = 'null'

    CIPHERS = [
        Utils.AES128,
        Utils.AES256,
        Utils.NULL,
    ]

    __INITIALIZATION_VECTOR = 'IV'
    __SESSION_KEY = 'SK'

    @staticmethod
    def init_vector(key, nonce):
        return Utils.__sha256_key(key, nonce, Utils.__INITIALIZATION_VECTOR)

    @staticmethod
    def session_key(key, nonce):
        return Utils.__sha256_key(key, nonce, Utils.__SESSION_KEY)

    @staticmethod
    def send_message(socket, msg, cipher, secret=None, nonce=None):
        data = msg.encode('utf-8')
        return Utils.send_data(data, socket, cipher, secret, nonce)

    def send_data(data, socket, cipher, secret=None, nonce=None):
        if cipher not in Utils.CIPHERS:
            raise ValueError('No such cipher: {}'.format(cipher))

        if cipher != Utils.NULL and (not secret or not nonce):
            raise ValueError('secret and nonce must be defined')

        return Utils.__encrypt(data, cipher, secret, nonce)


    @staticmethod
    def __sha256_key(key, nonce, type):

        m = hashlib.sha256()
        m.update(key)
        m.update(nonce)
        m.update(type)
        return m.digest()

    @staticmethod
    def __encrypt(data, cipher, secret, nonce):
        if cipher == Utils.NULL:
            return data

        elif cipher == Utils.AES128:
            key = Utils.__generate_key(secret, 128)
        elif cipher == Utils.AES256:
            key = Utils.__generate_key(secret, 256)

        aesccm = AESCCM(key)
        ct = aesccm.encrypt(nonce, data)
        return ct


    @staticmethod
    def __generate_key(secret, length):
        raise NotImplementedError()
