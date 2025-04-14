import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from RSA.RSA import generate_private_key, generate_public_key, export_keys

if __name__ == "__main__":
  # Générer les clés RSA
  private_key = generate_private_key()
  public_key = generate_public_key(private_key)
  private_pem, public_pem = export_keys(private_key, public_key)

  print("Génération des clés RSA...")

  # Utilise AES pour chiffrer un fichier
  from AES.AES import encrypt_to_file, key

  AES_key = key
  encrypt_to_file("message_secret.txt", "message_secret_chiffre.txt")

  print("Chiffrement du message...")

  # Transfert to paraminko
  from Paraminko.paraminko import transfer_file

  transfer_file("message_secret_chiffre.txt", "/Users/noahheraud/message_secret_chiffre.txt")

  print("Transfert du message chiffré...")

  # Ajoute une signature 

  from RSA.RSA import sign_message
  with open("message_secret_chiffre.txt", "rb") as f:
    message = f.read()

  print("Création de la signature...")

  signature = sign_message(private_key, message)

  print("Enregistrement de la signature...")

  with open("signature.txt", "wb") as f:
    f.write(signature)

  # Transfert to paraminko

  print("Transfert de la signature...")

  transfer_file("signature.txt", "/Users/noahheraud/signature.txt")

  print("✅ Chiffré, signé et transféré")

