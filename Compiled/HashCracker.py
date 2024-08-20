import hashlib
import binascii
from pwn import log

# edit this
salt  = binascii.unhexlify('▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒')  # 16 bytes Salt
key   = '▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒' # Hash
dklen = 50
iterations = 50000

def hash(password, salt, iterations, dklen):
    hashValue = hashlib.pbkdf2_hmac(
        hash_name='sha256', 
        password=password, 
        salt=salt, 
        iterations=iterations, 
        dklen=dklen,
        )
    return hashValue

dict = '/usr/share/wordlists/rockyou.txt'
bar  = log.progress('Cracking PBKDF2')
with open(dict, 'r', encoding='utf-8') as f:
    for line in f:
        password  = line.strip().encode('utf-8') 
        hashValue = hash(password, salt, iterations, dklen)
        target    = binascii.unhexlify(key)
        # log.info(f'Our target is: {target}')
        bar.status(f'Trying: {password}, hash: {hashValue}')
        if hashValue == target:
            bar.success(f'Found password: {password}!')
            break
        
    bar.failure('Hash is not crackable.')
