"""\nDecrypt Readium LCP encrypted audiobooks.\n"""
__license__ = 'GPL v3'
__version__ = '1'
from genericpath import exists
import argparse
from os.path import exists
import json
import hashlib
import base64
import binascii
import os.path
from zipfile import ZipFile
from Crypto.Cipher import AES

class Run:
    def __init__(self, key, file_path):
        self.path_to_ebook = file_path
        self.passphrase = key

    def start(self):
        decryptLCPbook(self.path_to_ebook, self.passphrase, self)



class Decryptor(object):
    def __init__(self, bookkey):
        self.book_key = bookkey

    def decrypt(self, data):
        aes = AES.new(self.book_key, AES.MODE_CBC, data[:16])
        data = aes.decrypt(data[16:])
        return data

class LCPError(Exception):
    pass

class LCPTransform:
    @staticmethod
    def secret_transform_basic(input_hash):
        return input_hash

    @staticmethod
    def secret_transform_profile10(input_hash):
        masterkey = 'b3a07c4d42880e69398e05392405050efeea0664c0b638b7c986556fa9b58d77b31a40eb6a4fdba1e4537229d9f779daad1cc41ee968153cb71f27dc9696d40f'
        masterkey = bytearray.fromhex(masterkey)
        current_hash = bytearray.fromhex(input_hash)
        for byte in masterkey:
            current_hash.append(byte)
            current_hash = bytearray(hashlib.sha256(current_hash).digest())
        return binascii.hexlify(current_hash).decode('latin-1')

    @staticmethod
    def userpass_to_hash(passphrase, algorithm):
        if algorithm == 'http://www.w3.org/2001/04/xmlenc#sha256':
            algo = 'SHA256'
            user_password_hashed = hashlib.sha256(passphrase).hexdigest()
            return (algo, user_password_hashed)
        print('LCP: Book is using unsupported user key algorithm: {0}'.format(algorithm))
        return (None, None)

def dataDecryptLCP(b64data, hex_key):
    try:
        iv = base64.decodebytes(b64data.encode('ascii'))[:16]
        cipher = base64.decodebytes(b64data.encode('ascii'))[16:]
    except AttributeError:
        iv = base64.decodestring(b64data.encode('ascii'))[:16]
        cipher = base64.decodestring(b64data.encode('ascii'))[16:]
    aes = AES.new(binascii.unhexlify(hex_key), AES.MODE_CBC, iv)
    temp = aes.decrypt(cipher)
    try:
        padding = temp[(-1)]
        data_temp = temp[:-padding]
    except TypeError:
        padding = ord(temp[(-1)])
        data_temp = temp[:-padding]
    return data_temp

def decryptLCPbook(inpath, passphrases, parent_object):
    zip_ref = ZipFile(inpath, 'r')
    with zip_ref.open('license.lcpl') as file:
            license = json.loads(file.read().decode('utf-8'))
    print('LCP: Found LCP-encrypted book {0}'.format(license['id']))
    if license['encryption']['profile'] == 'http://readium.org/lcp/basic-profile':
        print('LCP: Book is using lcp/basic-profile encryption.')
        transform_algo = LCPTransform.secret_transform_basic
    else:
        if license['encryption']['profile'] == 'http://readium.org/lcp/profile-1.0':
            print('LCP: Book is using lcp/profile-1.0 encryption')
            transform_algo = LCPTransform.secret_transform_profile10
        else:
            file.close()
            raise LCPError('Book is using an unknown LCP encryption standard: {0}'.format(license['encryption']['profile']))
    if 'algorithm' in license['encryption']['content_key']:
        if license['encryption']['content_key']['algorithm'] != 'http://www.w3.org/2001/04/xmlenc#aes256-cbc':
            file.close()
            raise LCPError('Book is using an unknown LCP encryption algorithm: {0}'.format(license['encryption']['content_key']['algorithm']))
    key_check = license['encryption']['user_key']['key_check']
    encrypted_content_key = license['encryption']['content_key']['encrypted_value']
    password_hashes = []
    if 'value' in license['encryption']['user_key']:
        try:
            password_hashes.append(binascii.hexlify(base64.decodebytes(license['encryption']['user_key']['value'].encode())).decode('ascii'))
        except AttributeError:
            password_hashes.append(binascii.hexlify(base64.decodestring(license['encryption']['user_key']['value'].encode())).decode('ascii'))
    if 'hex_value' in license['encryption']['user_key']:
        password_hashes.append(binascii.hexlify(bytearray.fromhex(license['encryption']['user_key']['hex_value'])).decode('ascii'))
    
    algo = 'http://www.w3.org/2001/04/xmlenc#sha256'
    if 'algorithm' in license['encryption']['user_key']:
        algo = license['encryption']['user_key']['algorithm']
    algo, tmp_pw = LCPTransform.userpass_to_hash(passphrases.encode('utf-8'), algo)
    if tmp_pw is not None:
        password_hashes.append(tmp_pw)
    correct_password_hash = None
    for possible_hash in password_hashes:
        transformed_hash = transform_algo(possible_hash)
        try:
            decrypted = None
            decrypted = dataDecryptLCP(key_check, transformed_hash)
        except:
            pass
        if decrypted is not None and decrypted.decode('ascii', errors='ignore') == license['id']:
            correct_password_hash = transformed_hash
            break
    if correct_password_hash is None:
        print('LCP: Tried {0} passphrases, but none of them could decrypt the book ...'.format(len(password_hashes)))
        if 'text_hint' in license['encryption']['user_key'] and license['encryption']['user_key']['text_hint'] != '':
            print('LCP: The book distributor has given you the following passphrase hint: \"{0}\"'.format(license['encryption']['user_key']['text_hint']))
        print('LCP: Enter the correct passphrase in the DeDRM plugin settings, then try again.')
        for link in license['links']:
            if 'rel' in link and link['rel'] == 'hint':
                print('LCP: You may be able to find or reset your LCP passphrase on the following webpage: {0}'.format(link['href']))
                break
        file.close()
        raise LCPError('No correct passphrase found')
    else:
        print('LCP: Found correct passphrase, decrypting book ...')
        decrypted_content_key = dataDecryptLCP(encrypted_content_key, correct_password_hash)
        if decrypted_content_key is None:
            raise LCPError('Decrypted content key is None')
        decryptor = Decryptor(decrypted_content_key)
        strippedPath = inpath.split('/')
        strippedFile = strippedPath[len(strippedPath) - 1].split('.')[0]
        outputFolder = inpath[:-(len(strippedPath) - 1)] + strippedFile



        if not os.path.exists(outputFolder):
            if not os.path.isdir(outputFolder):
                os.mkdir(outputFolder)

        with zip_ref.open('manifest.json') as manifest_file:
                manifest = json.loads(manifest_file.read().decode('utf-8'))


        hrefs = [item["href"] for item in manifest["readingOrder"]]


        for chapter in hrefs:
            with zip_ref.open(chapter) as chapter_file:
                pdfdata = chapter_file.read()

            outputname = os.path.join(outputFolder, chapter)
    

            with open(outputname, 'wb') as f:
                f.write(decryptor.decrypt(pdfdata))
            print('LCP: Chapter successfully decrypted, exporting to {0}'.format(outputname))
            
        for zipped in zip_ref.namelist():
            if zipped.endswith('.png') or zipped.endswith('.jpg') or zipped.endswith('.jpeg'):
                zip_ref.extract(zipped, outputFolder)
                print('Cover art successfully copied to output folder')


def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-key', type=str, required=True, help='Passphrase key')
    parser.add_argument('file_path', type=str, help='Path to the ebook file')

    args = parser.parse_args()

    run_instance = Run(args.key, args.file_path)
    run_instance.start()

if __name__ == '__main__':
    main()
