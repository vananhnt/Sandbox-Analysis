import math
import random
import sys

def generateRandomNumber(digits):
    finalNumber = ""
    for i in range(digits // 16):
        finalNumber = finalNumber + str(math.floor(random.random() * 10000000000000000))
    finalNumber = finalNumber + str(math.floor(random.random() * (10 ** (digits % 16))))
    return int(finalNumber)

# Generate a random password of length 12
password = generateRandomNumber(12)
print(sys.executable)