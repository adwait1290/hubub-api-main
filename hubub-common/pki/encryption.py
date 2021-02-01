import os, base64, logging
import requests
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

from kombu.transport.virtual import Base64

from hubub_common.pki.kms_client import KMSClient
from ..s3access import get_service_credentials
from ..util import make_authentication_headers

class PKIEncryption():

    async def encrypt(self, plaintext, key, auth_data=b""):
        if not isinstance(plaintext, bytes):
            data = bytes(plaintext, 'utf-8')
        aad = auth_data
        aesgcm = AESGCM(key)
        nonce = os.urandom(13)
        ct = aesgcm.encrypt(nonce, data, aad)
        return [ct, nonce]


    async def decrypt(self, key, package, auth_data=b""):
        try:
            ciphertext = package[0]
            nonce = package[1]
            aesgcm = AESGCM(key)
            data = aesgcm.decrypt(nonce, ciphertext, auth_data)
            return str(data, 'utf-8')
        except Exception as e:
            logging.getLogger().info("Exception decrypting key".format(e))
            return None


    ''' 
        validate a short string "plaintext" sent in the message header along with its own ciphertext
        this to confirm we have the right key to decrypt the message before we continue
    '''
    async def validate(self, key, package, plaintext):
        try:
            msg = self.decrypt(key, package)
        except Exception as e:
            logging.getLogger().info("Exception decrypting key for validation : ".format(e))
            return False
        if msg == plaintext:
            return True

    async def get_backend_private_key(self, app):
        kmsc = KMSClient(app)
        service_id, service_secret = get_service_credentials(app, "AUTHENTICATION_SERVICE")
        url = ''.join([app.hububconfig.get('KEYMANAGER_DEFAULT_URL'), '/api/v1/get_be_prvkey'])
        headers = make_authentication_headers(service_id, service_secret, url)
        headers.update({"Connection":"close"})
        response = requests.post(url, headers=headers, verify=False)

        if response.status_code == 200:
            json_response = response.json()
            encrypted_key = json_response.get('key')
            decoded_encrypted_key = base64.b64decode(encrypted_key)
            decrypted_key = kmsc.decrypt_using_kms(app=app, ciphertext=decoded_encrypted_key)
            return decrypted_key
        else:
            return None

    def rsa_encrypt(self, app, publickey, plaintext):
        # str = publickey.replace("-----BEGIN PUBLIC KEY-----\n","").replace("-----END PUBLIC KEY-----", "").replace("\n","")
        # decoded_key = base64.b64decode(str)
        # public_rsa_key = serialization.load_pem_public_key(publickey, backend=default_backend())
        public_key = RSA.importKey(publickey)
        cipher = PKCS1_OAEP.new(public_key)
        if not isinstance(plaintext, bytes):
            data = bytes(plaintext, 'utf-8')
        encrypted_blob = cipher.encrypt(data)
        encoded_encryption_blob = base64.b64encode(encrypted_blob)
        return encoded_encryption_blob

    def rsa_decrypt_encoded_blob(self, app, privatekey, encoded_blob):
        private_rsa_key = RSA.importKey(privatekey)
        cipher = PKCS1_OAEP.new(private_rsa_key)
        decoded_encryption_blob = base64.b64decode(encoded_blob)
        decrypted_data = cipher.decrypt(decoded_encryption_blob)
        return decrypted_data

    async def generate_AES_GCM_256_KEY(self):
        key = AESGCM.generate_key(bit_length=256)
        return key

    async def generate_RSA_KEYS(self):
        random_generator = Random.new().read
        private_key = RSA.generate(2048, random_generator)
        public_key = private_key.publickey()
        private_key_pem = private_key.exportKey('PEM')
        public_key_pem = public_key.exportKey('PEM')
        private_key_str = str(private_key_pem, 'utf-8')
        public_key_str = str(public_key_pem, 'utf-8')
        return private_key_str, public_key_str