import numpy as np
from sympy import Matrix
print("Welcome to Hill Cipher Encrypter, Decrypter.")
print("Enter 1 for Encryption Mode, 2 for Key Discovery:")

n=int(input())
while not(n==1 or n==2):
    print("Enter 1 for Encryption Mode, 2 for Key Discovery:")
    n=int(input())
# Encryption Mode.
if n==1:
    print("Encryption Mode.")
    print("Enter Plaintext to be encoded:")
    text=input()
    print("Enter the Key:")
    key=input()
    extras=0
    # modifying the input to be divisible by 3.
    if (len(text)%3==1):
        text=text+'XX'
        extras=2
    elif (len(text)%3==2):
        text=text+'X'
        extras=1
    else:
        text=text
        extras=0

    array_p=np.zeros((3,int(len(text)/3)))
    for i in range(len(text)):
        array_p[i%3][int(i/3)]=ord(text[i])

    array_p=array_p-65

    array_k=np.zeros((3,int(len(key)/3)))
    for i in range(len(key)):
        array_k[int(i/3)][int(i%3)]=ord(key[i])

    array_k=array_k-65
# converted inputs into numpy arrays
    cipher=np.matmul(array_k, array_p)
    cipher=cipher%26
    # print(cipher)
    # matrix multiplication to encrypt the message
    cip=""
    for col in range(cipher.shape[1]):
        for row in range(cipher.shape[0]):
            cip=cip+chr(int(cipher[row][col])+65)
    # extracting the message and printing
    print("Cipher Text is:")
    print(cip)

# Key Discovery Mode.    
else:
    print("Key Discovery.")
    print("Enter the Plain Text:")
    text=input()
    text=text[:9].upper()
    array_p=np.zeros((3,int(len(text)/3)),dtype=int)
    for i in range(len(text)):
        array_p[i%3][int(i/3)]=ord(text[i])

    P=array_p-65
    # print(array_p)
    print("Enter the Cipher Text:")
    cipher=input()
    cipher=cipher[:9].upper()

    array_c=np.zeros((3,int(len(cipher)/3)),dtype=int)
    for i in range(len(cipher)):
        array_c[i%3][int(i/3)]=ord(cipher[i])

    C=array_c-65
    # print(array_c)
    # print(P)
    # print(C)
    P_matrix = Matrix(P)
    C_matrix = Matrix(C)
# we have C=K*P mod 26
# we need to find K, knowing C and P.
    # print(P_matrix)
    # print(C_matrix)

    # Calculate the inverse of P modulo 26
    try:
        P_inv_mod26 = P_matrix.inv_mod(26)
    except ValueError:
        print("Matrix P is not invertible modulo 26.")
        # error if not invertible
        exit()

    # Calculate K
    K = (C_matrix * P_inv_mod26) % 26

    # Convert back to numpy array if needed
    K = np.array(K).astype(int)
# converting K into numpy matrix
    # print("Key matrix K:")
    # print(K)
    key=""
    for row in range(3):
        for col in range(3):
            key=key+chr(K[row][col]+65)
            #extracting the key and printing
    print("KEY is:")
    print(key)

## REMAINING TO OPTIMIZE THIS IF MESSAGE IS NOT CLEAR
        
    







    
