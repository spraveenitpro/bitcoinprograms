import hashlib
import binascii
import secp256k1  

# Calculate the hex of the private key from random bytes
# Prepend "80" and append "01" to the above generated hex represenation


def privatekeyinhex(val):
    hashobj = hashlib.sha256(val)
    priv_key_int = int.from_bytes(hashobj.digest(), 'big')
    priv_key_hex = '%064x' % priv_key_int
    print("Private Key Hex: {key} \n\n\n ". format(key=priv_key_hex))
    priv_key_and_version = "80" + priv_key_hex + "01"
    print("Private key with version & flag {key} \n\n\n".format(key=priv_key_and_version))
    return priv_key_hex, priv_key_and_version


priv_key_hex = privatekeyinhex(b"Bitcoins are cool")


# Calculate the public key from the private key via secp256k1 ECDSA curve

def privateKeyToPublicKey(val):
    privkey = secp256k1.PrivateKey(bytes(bytearray.fromhex(priv_key_hex[0])))
    pubkey_ser = privkey.pubkey.serialize()
    pubkey_ser_uncompressed = privkey.pubkey.serialize(compressed=False)
    return pubkey_ser.hex()

publickey = privateKeyToPublicKey(priv_key_hex)
print("Public key is {key} \n\n\n".format(key =publickey ))


# Calculate the first 4 bytes of the double SHA256 Hash of the private key

def getchecksum(val):
    hash = hashlib.sha256(bytes.fromhex(val))
    hx = hash.hexdigest()
    hash2 = hashlib.sha256(bytes.fromhex(hx))
    hx2 = hash2.hexdigest()
    checksum = hx2[:8]
    return checksum

# Print the private key with the checksum appended

checksum = getchecksum(priv_key_hex[1])
print("Checksum is {key} \n\n\n".format(key=checksum))
print("Private key with checksum is {key} \n\n\n".format(key=priv_key_hex[1] + checksum))

# Calculate Base58 of the input

def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add ‘1’ for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

# Print the base58 encoded private key with the checksum appended.

private_key = base58(priv_key_hex[1] + checksum)
print("Base58 of the private key is {key} \n\n\n".format(key=private_key))

# Calculate SHA256 + RIPEMD160 hash of the public key hex

def sha256ripemd160(value):
    publickey = binascii.unhexlify(value)
    s = hashlib.new('sha256', publickey).digest()
    r = hashlib.new('ripemd160',s).digest()
    publickeyhex = "00"+r.hex()
    return publickeyhex,r

publickeyhex = sha256ripemd160(publickey)

print("Hashing the public key with SHA256 and RIPEMD160 {key} \n\n\n".format(key=publickeyhex[0]))

# Calculate the checksum of the Public key hex and print it

newchecksum = getchecksum(publickeyhex[0])
print("New Checksum is {key} \n\n\n".format(key=newchecksum))

# Prepend 00 to the public key hex and append the checksum and print it

doublehashedpublickey = "00" + publickeyhex[1].hex() + newchecksum
print("Private key with checksum is {key} \n\n\n".format(key=doublehashedpublickey))

# Calculate the BASE58 encoded version of the above public key and print it

print("Final Base58 encoded public address is: {key}".format(key=base58(doublehashedpublickey)))

