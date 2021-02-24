from pwn import *

def xorString(str1, str2):
    res = b""
    for a,b in zip(bytes.fromhex(str1), bytes.fromhex(str2)):
        res += bytes([a^b])
    return res.hex()

def makeMessage(blocks):
    message = ""
    for block in blocks:
        for item in block:
            message += item
    return message

originalCipher = [
"5468697320697320616e204956343536",
"0ca408a2aaa734602e0153fcfdeb575a",
"c8ee13cdf1c60b0958cbcbaa6bc05c73",
"5f7c31bd2e3d068a5dfcb8cead861c65",
"320446515d3195fd21983d7354666bfd"
]
originalCipher = "".join(originalCipher)

semiCipher = [
['2f', '4a', '1c', '00', '45', '1b', '1d', '41', '0c', '0b', '02', '73', '76', '16', '52', '43'],
['69', 'd7', '7c', '80', '86', '87', '16', '05', '56', '71', '3a', '8e', '98', '98', '75', '60'],
['e8', 'cc', '21', 'fd', 'c1', 'f6', '26', '39', '69', 'e6', 'fb', '9d', '49', 'ec', '7c', '51'],
['36', '0f', '6e', 'dc', '4a', '50', '6f', 'e4', '7f', 'c6', '98', 'ec', 'cb', 'e7', '70', '16'],
['57', '26', '3b', '5c', '50', '3c', '98', 'f0', '2c', '95', '30', '7e', '59', '6b', '66', 'f0']
]
semiCipher = makeMessage(semiCipher)
print(f"semiCipher: {semiCipher}")

originalPlain = xorString(originalCipher, semiCipher)
originalCookie = bytes.fromhex(originalPlain)
print(f"original Cookie: {originalCookie}")