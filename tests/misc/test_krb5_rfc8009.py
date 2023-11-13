from impacket.krb5.crypto import _AES256_SHA384_CTS, _SHA384AES256
from Cryptodome.Hash import HMAC
from struct import pack
import unittest

class Aes256HmacSha384Tests(unittest.TestCase):
    etype = _AES256_SHA384_CTS
    digest = _SHA384AES256

    def test_encrypt_empty_plaintext(self):
        plaintext = b''
        confounder = bytes.fromhex('F7 64 E9 FA 15 C2 76 47 8B 2C 7D 0C 4E 5F 58 E4')
        Ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
        Ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
        exp_ciphertext = bytes.fromhex('41 F5 3F A5 BF E7 02 6D 91 FA F9 BE 95 91 95 A0 58 70 72 73 A9 6A 40 F0 A0 19 60 62 1A C6 12 74 8B 9B BF BE 7E B4 CE 3C')
        key=self.etype.random_to_key(Ke)
        C = self.etype.basic_encrypt(key, confounder + plaintext, bytes(self.etype.blocksize))
        H = HMAC.new(Ki, bytes(self.etype.blocksize) + C, self.etype.hashmod).digest()[:self.etype.macsize]
        ciphertext = C + H
        self.assertEqual(ciphertext, exp_ciphertext)
        C = ciphertext[:-self.etype.macsize]
        H = ciphertext[-self.etype.macsize:]
        dec_plaintext = self.etype.basic_decrypt(key, C, bytes(self.etype.blocksize))[len(confounder):]
        self.assertEqual(plaintext, dec_plaintext)
        self.assertEqual(H, HMAC.new(Ki, bytes(self.etype.blocksize) + C, self.etype.hashmod).digest()[:self.etype.macsize])

        ciphertext = self.etype.encrypt(key, 2, plaintext, confounder)
        dec_plaintext = self.etype.decrypt(key, 2, ciphertext)
        self.assertEqual(plaintext, dec_plaintext)

    def test_encrypt_less_than_block_size(self):
        plaintext = bytes.fromhex('00 01 02 03 04 05')
        confounder = bytes.fromhex('B8 0D 32 51 C1 F6 47 14 94 25 6F FE 71 2D 0B 9A')
        Ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
        Ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
        exp_ciphertext = bytes.fromhex('4E D7 B3 7C 2B CA C8 F7 4F 23 C1 CF 07 E6 2B C7 B7 5F B3 F6 37 B9 F5 59 C7 F6 64 F6 9E AB 7B 60 92 23 75 26 EA 0D 1F 61 CB 20 D6 9D 10 F2')
        key=self.etype.random_to_key(Ke)
        C = self.etype.basic_encrypt(key, confounder + plaintext, bytes(self.etype.blocksize))
        H = HMAC.new(Ki, bytes(self.etype.blocksize) + C, self.etype.hashmod).digest()[:self.etype.macsize]
        ciphertext = C + H
        self.assertEqual(ciphertext, exp_ciphertext)
        C = ciphertext[:-self.etype.macsize]
        H = ciphertext[-self.etype.macsize:]
        dec_plaintext = self.etype.basic_decrypt(key, C, bytes(self.etype.blocksize))[len(confounder):]
        self.assertEqual(plaintext, dec_plaintext)
        self.assertEqual(H, HMAC.new(Ki, bytes(self.etype.blocksize) + C, self.etype.hashmod).digest()[:self.etype.macsize])

        ciphertext = self.etype.encrypt(key, 2, plaintext, confounder)
        dec_plaintext = self.etype.decrypt(key, 2, ciphertext)
        self.assertEqual(plaintext, dec_plaintext)

    def test_encrypt_equals_block_size(self):
        plaintext = bytes.fromhex('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F')
        confounder = bytes.fromhex('53 BF 8A 0D 10 52 65 D4 E2 76 42 86 24 CE 5E 63')
        Ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
        Ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
        exp_ciphertext = bytes.fromhex('BC 47 FF EC 79 98 EB 91 E8 11 5C F8 D1 9D AC 4B BB E2 E1 63 E8 7D D3 7F 49 BE CA 92 02 77 64 F6 8C F5 1F 14 D7 98 C2 27 3F 35 DF 57 4D 1F 93 2E 40 C4 FF 25 5B 36 A2 66')
        key=self.etype.random_to_key(Ke)
        C = self.etype.basic_encrypt(key, confounder + plaintext, bytes(self.etype.blocksize))
        H = HMAC.new(Ki, bytes(self.etype.blocksize) + C, self.etype.hashmod).digest()[:self.etype.macsize]
        ciphertext = C + H
        self.assertEqual(ciphertext, exp_ciphertext)
        C = ciphertext[:-self.etype.macsize]
        H = ciphertext[-self.etype.macsize:]
        dec_plaintext = self.etype.basic_decrypt(key, C, bytes(self.etype.blocksize))[len(confounder):]
        self.assertEqual(plaintext, dec_plaintext)
        self.assertEqual(H, HMAC.new(Ki, bytes(self.etype.blocksize) + C, self.etype.hashmod).digest()[:self.etype.macsize])

        ciphertext = self.etype.encrypt(key, 2, plaintext, confounder)
        dec_plaintext = self.etype.decrypt(key, 2, ciphertext)
        self.assertEqual(plaintext, dec_plaintext)

    def test_encrypt_greater_than_block_size(self):
        plaintext = bytes.fromhex('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14')
        confounder = bytes.fromhex('76 3E 65 36 7E 86 4F 02 F5 51 53 C7 E3 B5 8A F1')
        Ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
        Ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
        exp_ciphertext = bytes.fromhex('40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE 10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2 B2 A6 02 AC 86 FE F6 EC B6 47 D6 29 5F AE 07 7A 1F EB 51 75 08 D2 C1 6B 41 92 E0 1F 62')
        key=self.etype.random_to_key(Ke)
        C = self.etype.basic_encrypt(key, confounder + plaintext, bytes(self.etype.blocksize))
        H = HMAC.new(Ki, bytes(self.etype.blocksize) + C, self.etype.hashmod).digest()[:self.etype.macsize]
        ciphertext = C + H
        self.assertEqual(ciphertext, exp_ciphertext)
        C = ciphertext[:-self.etype.macsize]
        H = ciphertext[-self.etype.macsize:]
        dec_plaintext = self.etype.basic_decrypt(key, C, bytes(self.etype.blocksize))[len(confounder):]
        self.assertEqual(plaintext, dec_plaintext)
        self.assertEqual(H, HMAC.new(Ki, bytes(self.etype.blocksize) + C, self.etype.hashmod).digest()[:self.etype.macsize])

        ciphertext = self.etype.encrypt(key, 2, plaintext, None)
        dec_plaintext = self.etype.decrypt(key, 2, ciphertext)
        self.assertEqual(plaintext, dec_plaintext)

    def test_prf(self):
        inpt = b'test'
        exp_output = bytes.fromhex('98 01 F6 9A 36 8C 2B F6 75 E5 95 21 E1 77 D9 A0 7F 67 EF E1 CF DE 8D 3C 8D 6F 6A 02 56 E3 B1 7D B3 C1 B6 2A D1 B8 55 33 60 D1 73 67 EB 15 14 D2')
        key=bytes.fromhex('6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98 00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52')
        message=bytes.fromhex('00 00 00 01 70 72 66 00 74 65 73 74 00 00 01 80')
        #output = self.etype.kdf_hmac_sha2(key=key, k=self.etype.seedsize, label=b'prf', context=b'test')
        output = self.etype.prf(self.etype.random_to_key(key), inpt)
        self.assertEqual(output, exp_output)

    def test_string_to_key(self):
        iter_count = 32768
        pw = b'password'
        salt = bytes.fromhex('10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61') + b'ATHENA.MIT.EDUraeburn'
        exp_key = bytes.fromhex('45 BD 80 6D BF 6A 83 3A 9C FF C1 C9 45 89 A2 22 36 7A 79 BC 21 C4 13 71 89 06 E9 F5 78 A7 84 67')
        key = self.etype.string_to_key(pw, salt, None)
        #print(" ".join("{:02X}".format(c) for c in exp_key))
        #print(" ".join("{:02X}".format(c) for c in key.contents))
        self.assertEqual(key.contents, exp_key)

    def test_key_derivation(self):
        keyusage = 2
        base_key = bytes.fromhex('6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98 00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52')
        exp_ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
        exp_ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
        exp_kc = bytes.fromhex('EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4 BA 41 F2 8F AF 69 E7 3D')
        key = self.etype.random_to_key(base_key)
        Ke = self.etype.random_to_key(self.etype.kdf_hmac_sha2(key.contents, pack('>IB', keyusage, 0xAA), self.etype.keysize))
        Ki = self.etype.random_to_key(self.etype.kdf_hmac_sha2(key.contents, pack('>IB', keyusage, 0x55), self.etype.macsize))
        Kc = self.etype.derive(key, pack('>IB', keyusage, 0x99))
        self.assertEqual(exp_ke, Ke.contents)
        self.assertEqual(exp_ki, Ki.contents)
        self.assertEqual(exp_kc, Kc.contents)

    def test_checksum(self):
        Kc = bytes.fromhex('EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4 BA 41 F2 8F AF 69 E7 3D')
        plaintext = bytes.fromhex('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14')
        exp_checksum = bytes.fromhex('45 EE 79 15 67 EE FC A3 7F 4A C1 E0 22 2D E8 0D 43 C3 BF A0 66 99 67 2A')
        checksum = HMAC.new(Kc, plaintext, self.digest.enc.hashmod).digest()[:self.digest.enc.macsize]
        self.assertEqual(checksum, exp_checksum)

if __name__ == '__main__':
    unittest.main(verbosity=1)
