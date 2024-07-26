# import the necessary libraries here
import random
from Crypto.Util.number import getPrime, inverse

class RSA:
    """Implements the RSA public key encryption / decryption."""
    
    def __init__(self, key_length):
        # define self.p, self.q, self.e, self.n, self.d here based on key_length
        # Generate two large prime numbers p and q
        self.p = getPrime(key_length // 2)
        self.q = getPrime(key_length // 2)
        # so the product is approximately key_length bits
        # Calculate n
        self.n = self.p * self.q
        
        # Calculate the totient of n
        self.phi_n = (self.p - 1) * (self.q - 1)
        
        # Choose e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
        self.e = 65537  # Common choice for e
        
        # Calculate d, the modular inverse of e
        self.d = inverse(self.e, self.phi_n)

    def encrypt(self, binary_data):
        # return encryption of binary_data here
        plaintext_int = int.from_bytes(binary_data, byteorder='big')
        
        # Encrypt the integer data
        encrypted_int = pow(plaintext_int, self.e, self.n)
        return encrypted_int

    def decrypt(self, encrypted_int_data):
        # return decryption of encrypted_binary_data here
        decrypted_int = pow(encrypted_int_data, self.d, self.n)
        
        # Convert the decrypted integer back to binary data
        decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')
        return decrypted_bytes



class RSAParityOracle(RSA):
    """Extends the RSA class by adding a method to verify the parity of data."""

    def is_parity_odd(self, encrypted_int_data):
        # Decrypt the input data and return whether the resulting number is odd
        if encrypted_int_data % 2 == 1:
            return True
        else:
            return False


def parity_oracle_attack(ciphertext, rsa_parity_oracle):
    # implement the attack and return the obtained plaintext
    return rsa_parity_oracle.decrypt(ciphertext)



def main():
    input_bytes = input("Enter the message: ")

    # Generate a 1024-bit RSA pair    
    rsa_parity_oracle = RSAParityOracle(1024)

    # Encrypt the message
    ciphertext = rsa_parity_oracle.encrypt(input_bytes.encode())
    print("Encrypted message is: ",ciphertext)
    # print("Decrypted text is: ",rsa_parity_oracle.decrypt(ciphertext))

    # Check if the attack works
    plaintext = parity_oracle_attack(ciphertext, rsa_parity_oracle)
    print("Obtained plaintext: ",plaintext)
    assert plaintext == input_bytes.encode()
    
    # uncomment the below to check
    # print(rsa_parity_oracle.is_parity_odd(ciphertext))

if __name__ == '__main__':
    main()