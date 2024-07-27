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
        decrypted_int = pow(encrypted_int_data, self.d, self.n)
        return decrypted_int % 2 == 1


def parity_oracle_attack(ciphertext, rsa_parity_oracle):
    # implement the attack and return the obtained plaintext
    lower_bound = 0
    upper_bound = rsa_parity_oracle.n

    # Precompute 2^e mod n
    factor = pow(2, rsa_parity_oracle.e, rsa_parity_oracle.n)
    
    current_ct = ciphertext

    # Start binary search
    for _ in range(rsa_parity_oracle.n.bit_length()):
        # Multiply the ciphertext by the factor to adjust the encrypted message
        current_ct = (current_ct * factor) % rsa_parity_oracle.n

        # Query the oracle
        if rsa_parity_oracle.is_parity_odd(current_ct):
            # If the result is odd, the plaintext is in the upper half of the current interval
            lower_bound = (lower_bound + upper_bound) // 2
        else:
            # If the result is even, the plaintext is in the lower half
            upper_bound = (lower_bound + upper_bound) // 2

    # The message integer is now very close to one of the bounds
    decrypted_int = lower_bound

    # Convert the decrypted integer back to bytes
    decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')
    return decrypted_bytes



def main():
    input_bytes = input("Enter the message: ")
    input_bytes+='g'
    # Generate a 1024-bit RSA pair
    rsa_parity_oracle = RSAParityOracle(1024)

    # Encrypt the message
    ciphertext = rsa_parity_oracle.encrypt(input_bytes.encode())
    print("Encrypted message is: ",ciphertext)
    # print("Decrypted text is: ",rsa_parity_oracle.decrypt(ciphertext))

    # Check if the attack works
    plaintext = parity_oracle_attack(ciphertext, rsa_parity_oracle)[:-1]
    print("Obtained plaintext: ",plaintext)
    assert plaintext == input_bytes[:-1].encode()

if __name__ == '__main__':
    main()
