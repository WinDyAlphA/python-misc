from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding



def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key
def generate_public_key(private_key):
    public_key = private_key.public_key()
    return public_key

def export_keys(private_key, public_key):
  private_pem = private_key.private_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PrivateFormat.PKCS8,
  encryption_algorithm=serialization.NoEncryption()
  )
  public_pem = public_key.public_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo
  )
  return private_pem, public_pem

def sign_message(private_key, message):
  signature = private_key.sign(
    message,
    padding.PSS(
      mgf=padding.MGF1(hashes.SHA256()),
      salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
  )
  return signature

def verify_message(public_key, message, signature):
  try:
    public_key.verify(
      signature,
      message,  
      padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH),
      hashes.SHA256()
    )
    return True
  except Exception as e:
    return False

if __name__ == "__main__":
  private_key = generate_private_key()
  public_key = generate_public_key(private_key)
  private_pem, public_pem = export_keys(private_key, public_key)

  print("Clé privée: \n", private_pem.decode())
  print("Clé publique: \n", public_pem.decode())

  message = b"Message a signer"
  signature = sign_message(private_key, message)
  print("Signature: \n", signature)

  is_valid = verify_message(public_key, message, signature)
  print("Signature valide: \n", is_valid)
