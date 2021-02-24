from pwn import *
import copy

context.log_level = 'error'

context.proxy = (socks.SOCKS5, 'localhost', 8123)

"""
Encrypt Attack:
semiCipher = validCipher ^ Padding
targetCiphter = semiCipher ^ targetPlain

The last Cipher Block: is same as the original
db84f4baf0a79081e1794bd58186cc0a


original plaintext:
b'{"username": "guest", "expires": "2000-01-07", "is_admin": "false"}\r\r\r\r\r\r\r\r\r\r\r\r\r'
"""

def xorString(str1, str2):
    res = b""
    for a,b in zip(bytes.fromhex(str1), bytes.fromhex(str2)):
        res += bytes([a^b])
    return res.hex()

def getPadding(i):
    return str("{:02x}".format(16-i))

def makeMessage(blocks):
    message = ""
    for block in blocks:
        for item in block:
            message += item
    return message

targetCookie = b'{"username": "guest", "expires": "2022-01-07", "is_admin": "true"}'
targetHex = targetCookie.hex()

padding = 16 - len(targetCookie)%16
x = str("{:02x}".format(padding))

for p in range(padding):
    targetHex += x

## Spliting target ciphertext
targetPlain = []
for block in [targetHex[i:i+32] for i in range(0, len(targetHex), 32)]:
    temp = [block[i:i+2] for i in range(0, len(block), 2)]
    targetPlain.append(temp)
print(f"targetPlain: \n{targetPlain}\n")

validCipher = [["" for _ in range(16)] for _ in range(6)]
semiCipher = [["" for _ in range(16)] for _ in range(6)]
targetCipher = [["00" for _ in range(16)] for _ in range(6)]


## Exploiting exisiting information
temp = xorString('57263b5c503c98f02c95307e596b66f0', '227d0e0e0e0e0e0e0e0e0e0e0e0e0e0e')
targetCipher[4] = [temp[i:i+2] for i in range(0, len(temp), 2)]

temp = "db84f4baf0a79081e1794bd58186cc0a"
targetCipher[5] = [temp[i:i+2] for i in range(0, len(temp), 2)]


print(f"targetCipher: \n{targetCipher}\n")

for b in range(3, -1, -1): ## from T[3] to T[0]
    sendBlocks = copy.deepcopy(targetCipher[:b+2])
    for i in range(15,-1,-1):
        padding = getPadding(i)
        for j in range(i+1,16):
            temp = xorString(semiCipher[b][j], padding)
            sendBlocks[b][j] = temp

        for v in range(256):
            x = str("{:02x}".format(v))
            print(f"Block: {b}, Byte {i}, Value {x}")
            
            sendBlocks[b][i] = x
            sendMessage = makeMessage(sendBlocks)
            
            oracle = remote('192.168.2.83', 32830)
            oracle.recvuntil('?\n')
            oracle.sendline(sendMessage)
            response = oracle.recvline()
            oracle.close()

            if b'invalid' not in response and x != targetCipher[b][i]:
                print(f"{x} is a Valid byte\n")
                validCipher[b][i] = x
                semiCipher[b][i] = xorString(validCipher[b][i], padding)
                targetCipher[b][i] = xorString(targetPlain[b][i], semiCipher[b][i])
                break


print(f"validCipher: \n{makeMessage(validCipher)}\n")
print(f"semiCipher: \n{makeMessage(semiCipher)}\n")
print(f"targetCipher: \n{makeMessage(targetCipher)}\n")


## The flag is: 715781cbe0fedee30fe84273d02a94a5
