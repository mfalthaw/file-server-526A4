import hashlib

class Utils:
  INITIALIZATION_VECTOR = 'IV'
  SESSION_KEY = 'SK'

  __HASH_TYPES = [
    Utils.INITIALIZATION_VECTOR,
    Utils.SESSION_KEY
  ]

  def __init__(self):
    pass

  def init_vector(key, nonce):
    pass

  def session_key(key, nonce):
    pass

  def __sha256_key(key, nonce, type):
    # Validate type
    if type not in Utils.__HASH_TYPES:
      raise ValueError('{} is an invalid type'.format(type))

    m = hashlib.sha256()
    m.update(key)
    m.update(nonce)
    m.update(type)
    return m.digest()
