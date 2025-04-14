import paramiko
import os

def transfer_file(file_path, remote_path):    
    transport = paramiko.Transport(("10.100.14.250", 22))
    transport.connect(username="noahheraud", password="PasswordSecret123!!")

    sftp = paramiko.SFTPClient.from_transport(transport)


    sftp.put(file_path, remote_path)

    sftp.close()
    transport.close()

#--------------------------------

def execute_command(command):
  ssh_client = paramiko.SSHClient()
  ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh_client.connect(hostname="10.100.14.250", username="noahheraud", password="PasswordSecret123!!")

  stdin, stdout, stderr = ssh_client.exec_command(command)

  print(stdout.read().decode())

  ssh_client.close()


if __name__ == "__main__":
   transfer_file("test.txt", "/Users/noahheraud/test.txt")
   execute_command("ls -l")