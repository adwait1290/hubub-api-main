"""
Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
in compliance with the License. A copy of the License is located at

https://aws.amazon.com/apache-2-0/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""

import filecmp

import boto3
import os


class KMSClient():
    def __init__(self, app):
        self.client = boto3.client("kms", region_name='us-east-1', aws_access_key_id=app.hububconfig.get('aws_kms_access_key'), aws_secret_access_key=app.hububconfig.get('aws_kms_secret_key'))

    def encrypt_using_kms(self, app, data):
        if isinstance(data, str):
            data = bytes(data, "utf-8")

        client = self.client
        response = client.encrypt(KeyId=app.hububconfig.get('aws_external_key_arn'),
                                  Plaintext=data
                                )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            cipher_text = response['CiphertextBlob']
            return cipher_text
        return None

    def decrypt_using_kms(self, app, ciphertext):

        client = self.client
        response = client.decrypt(CiphertextBlob = ciphertext)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            decrypted_text = response['Plaintext']
            if isinstance(decrypted_text, bytes):
                decrypted_text = decrypted_text.decode('utf-8')
            return decrypted_text
        return None


