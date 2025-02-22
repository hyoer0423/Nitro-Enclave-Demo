import socket
import requests
import json
import boto3
import random
def aws_api_call(credential):
    """
    Make AWS API call using credential obtained from parent EC2 instance
    """

    client = boto3.client(
        'kms',
        region_name = 'ap-northeast-1',
        aws_access_key_id = credential['access_key_id'],
        aws_secret_access_key = credential['secret_access_key'],
        aws_session_token = credential['token']
    )
    desc='Customer Master Key'
    source_plaintext=random.randint(000000,999999)
    source_plaintext=str(source_plaintext)
    source_plaintext=str.encode(source_plaintext)
    response = client.create_key(Description=desc)
    # This is just a demo API call to demonstrate that we can talk to AWS via API
    ciphertext = client.encrypt(Plaintext=source_plaintext, KeyId=response['KeyMetadata']['KeyId'],EncryptionAlgorithm='SYMMETRIC_DEFAULT')
    print(ciphertext)
    cycled_plaintext = client.decrypt(CiphertextBlob=ciphertext['CiphertextBlob'], KeyId=response['KeyMetadata']['KeyId'],EncryptionAlgorithm='SYMMETRIC_DEFAULT')
    print(cycled_plaintext)
    

    # Return some data from API response
    return {
        'Plaintext':source_plaintext.decode(),
        'Ciphertext': ciphertext['CiphertextBlob'],
        'Decryptedtext': cycled_plaintext['Plaintext'].decode()
    }

def main():
    print("Starting server...")
    
    # Create a vsock socket object
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Listen for connection from any CID
    cid = socket.VMADDR_CID_ANY

    # The port should match the client running in parent EC2 instance
    port = 5000

    # Bind the socket to CID and port

    s.bind((cid, port))

    # Listen for connection from client
    s.listen()

    while True:
        c, addr = s.accept()

        # Get AWS credential sent from parent instance
        payload = c.recv(4096)
        credential = json.loads(payload.decode())

        # Get data from AWS API call
        content = aws_api_call(credential)

        # Send the response back to parent instance
        c.send(str.encode(str(content)))

        # Close the connection
        c.close() 

if __name__ == '__main__':
    main()
