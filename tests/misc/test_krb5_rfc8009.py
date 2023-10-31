from impacket.krb5.crypto import _AES256_SHA384_CTS
from Cryptodome.Hash import HMAC
from struct import pack

cls = _AES256_SHA384_CTS

plaintext = b''
confounder = bytes.fromhex('F7 64 E9 FA 15 C2 76 47 8B 2C 7D 0C 4E 5F 58 E4')
Ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
Ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
exp_ciphertext = bytes.fromhex('41 F5 3F A5 BF E7 02 6D 91 FA F9 BE 95 91 95 A0 58 70 72 73 A9 6A 40 F0 A0 19 60 62 1A C6 12 74 8B 9B BF BE 7E B4 CE 3C')
key=cls.random_to_key(Ke)
C = cls.basic_encrypt(key, confounder + plaintext, bytes(cls.blocksize))
H = HMAC.new(Ki, bytes(cls.blocksize) + C, cls.hashmod).digest()[:cls.macsize]
ciphertext = C + H
assert(ciphertext == exp_ciphertext)
C = ciphertext[:-cls.macsize]
H = ciphertext[-cls.macsize:]
dec_plaintext = cls.basic_decrypt(key, C, bytes(cls.blocksize))[len(confounder):]
assert(plaintext == dec_plaintext)
assert(H == HMAC.new(Ki, bytes(cls.blocksize) + C, cls.hashmod).digest()[:cls.macsize])

ciphertext = cls.encrypt(key, 2, plaintext, confounder)
dec_plaintext = cls.decrypt(key, 2, ciphertext)
assert(plaintext == dec_plaintext)

plaintext = bytes.fromhex('00 01 02 03 04 05')
confounder = bytes.fromhex('B8 0D 32 51 C1 F6 47 14 94 25 6F FE 71 2D 0B 9A')
Ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
Ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
exp_ciphertext = bytes.fromhex('4E D7 B3 7C 2B CA C8 F7 4F 23 C1 CF 07 E6 2B C7 B7 5F B3 F6 37 B9 F5 59 C7 F6 64 F6 9E AB 7B 60 92 23 75 26 EA 0D 1F 61 CB 20 D6 9D 10 F2')
key=cls.random_to_key(Ke)
C = cls.basic_encrypt(key, confounder + plaintext, bytes(cls.blocksize))
H = HMAC.new(Ki, bytes(cls.blocksize) + C, cls.hashmod).digest()[:cls.macsize]
ciphertext = C + H
assert(ciphertext == exp_ciphertext)
C = ciphertext[:-cls.macsize]
H = ciphertext[-cls.macsize:]
dec_plaintext = cls.basic_decrypt(key, C, bytes(cls.blocksize))[len(confounder):]
assert(plaintext == dec_plaintext)
assert(H == HMAC.new(Ki, bytes(cls.blocksize) + C, cls.hashmod).digest()[:cls.macsize])

ciphertext = cls.encrypt(key, 2, plaintext, confounder)
dec_plaintext = cls.decrypt(key, 2, ciphertext)
assert(plaintext == dec_plaintext)

plaintext = bytes.fromhex('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F')
confounder = bytes.fromhex('53 BF 8A 0D 10 52 65 D4 E2 76 42 86 24 CE 5E 63')
Ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
Ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
exp_ciphertext = bytes.fromhex('BC 47 FF EC 79 98 EB 91 E8 11 5C F8 D1 9D AC 4B BB E2 E1 63 E8 7D D3 7F 49 BE CA 92 02 77 64 F6 8C F5 1F 14 D7 98 C2 27 3F 35 DF 57 4D 1F 93 2E 40 C4 FF 25 5B 36 A2 66')
key=cls.random_to_key(Ke)
C = cls.basic_encrypt(key, confounder + plaintext, bytes(cls.blocksize))
H = HMAC.new(Ki, bytes(cls.blocksize) + C, cls.hashmod).digest()[:cls.macsize]
ciphertext = C + H
assert(ciphertext == exp_ciphertext)
C = ciphertext[:-cls.macsize]
H = ciphertext[-cls.macsize:]
dec_plaintext = cls.basic_decrypt(key, C, bytes(cls.blocksize))[len(confounder):]
assert(plaintext == dec_plaintext)
assert(H == HMAC.new(Ki, bytes(cls.blocksize) + C, cls.hashmod).digest()[:cls.macsize])

ciphertext = cls.encrypt(key, 2, plaintext, confounder)
dec_plaintext = cls.decrypt(key, 2, ciphertext)
assert(plaintext == dec_plaintext)

plaintext = bytes.fromhex('00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14')
confounder = bytes.fromhex('76 3E 65 36 7E 86 4F 02 F5 51 53 C7 E3 B5 8A F1')
Ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
Ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
exp_ciphertext = bytes.fromhex('40 01 3E 2D F5 8E 87 51 95 7D 28 78 BC D2 D6 FE 10 1C CF D5 56 CB 1E AE 79 DB 3C 3E E8 64 29 F2 B2 A6 02 AC 86 FE F6 EC B6 47 D6 29 5F AE 07 7A 1F EB 51 75 08 D2 C1 6B 41 92 E0 1F 62')
key=cls.random_to_key(Ke)
C = cls.basic_encrypt(key, confounder + plaintext, bytes(cls.blocksize))
H = HMAC.new(Ki, bytes(cls.blocksize) + C, cls.hashmod).digest()[:cls.macsize]
ciphertext = C + H
assert(ciphertext == exp_ciphertext)
C = ciphertext[:-cls.macsize]
H = ciphertext[-cls.macsize:]
dec_plaintext = cls.basic_decrypt(key, C, bytes(cls.blocksize))[len(confounder):]
assert(plaintext == dec_plaintext)
assert(H == HMAC.new(Ki, bytes(cls.blocksize) + C, cls.hashmod).digest()[:cls.macsize])

ciphertext = cls.encrypt(key, 2, plaintext, None)
dec_plaintext = cls.decrypt(key, 2, ciphertext)
assert(plaintext == dec_plaintext)

inpt = b'test'
exp_output = bytes.fromhex('98 01 F6 9A 36 8C 2B F6 75 E5 95 21 E1 77 D9 A0 7F 67 EF E1 CF DE 8D 3C 8D 6F 6A 02 56 E3 B1 7D B3 C1 B6 2A D1 B8 55 33 60 D1 73 67 EB 15 14 D2')
key=bytes.fromhex('6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98 00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52')
message=bytes.fromhex('00 00 00 01 70 72 66 00 74 65 73 74 00 00 01 80')
#output = cls.kdf_hmac_sha2(key=key, k=cls.seedsize, label=b'prf', context=b'test')
output = cls.prf(cls.random_to_key(key), inpt)
assert(output == exp_output)

iter_count = 32768
pw = b'password'
salt = bytes.fromhex('10 DF 9D D7 83 E5 BC 8A CE A1 73 0E 74 35 5F 61') + b'ATHENA.MIT.EDUraeburn'
exp_key = bytes.fromhex('45 BD 80 6D BF 6A 83 3A 9C FF C1 C9 45 89 A2 22 36 7A 79 BC 21 C4 13 71 89 06 E9 F5 78 A7 84 67')
key = cls.string_to_key(pw, salt, None)
#print(" ".join("{:02X}".format(c) for c in exp_key))
#print(" ".join("{:02X}".format(c) for c in key.contents))
assert(key.contents == exp_key)

keyusage = 2
base_key = bytes.fromhex('6D 40 4D 37 FA F7 9F 9D F0 D3 35 68 D3 20 66 98 00 EB 48 36 47 2E A8 A0 26 D1 6B 71 82 46 0C 52')
exp_ke = bytes.fromhex('56 AB 22 BE E6 3D 82 D7 BC 52 27 F6 77 3F 8E A7 A5 EB 1C 82 51 60 C3 83 12 98 0C 44 2E 5C 7E 49')
exp_ki = bytes.fromhex('69 B1 65 14 E3 CD 8E 56 B8 20 10 D5 C7 30 12 B6 22 C4 D0 0F FC 23 ED 1F')
exp_kc = bytes.fromhex('EF 57 18 BE 86 CC 84 96 3D 8B BB 50 31 E9 F5 C4 BA 41 F2 8F AF 69 E7 3D')
key = cls.random_to_key(base_key)
Ke = cls.random_to_key(cls.kdf_hmac_sha2(key.contents, pack('>IB', keyusage, 0xAA), cls.keysize))
Ki = cls.random_to_key(cls.kdf_hmac_sha2(key.contents, pack('>IB', keyusage, 0x55), cls.macsize))
Kc = cls.derive(key, pack('>IB', keyusage, 0x99))
assert(exp_ke == Ke.contents)
assert(exp_ki == Ki.contents)
assert(exp_kc == Kc.contents)
