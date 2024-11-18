from dataclasses import dataclass  # Import dataclass decorator for easy class initialization

# SNOW-V Cipher Class
@dataclass
class SnowVCipher:

    # AES S-Box: Substitution box used for byte substitution in encryption
    SBox = [
        0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
        0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
        0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
        0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
        0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
        0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
        0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
        0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
        0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
        0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
        0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
        0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
        0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
        0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
        0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
        0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
    ]

    # Sigma permutation for byte ordering or mixing
    Sigma = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]

    def __init__(self):
        """
        Initialize the SnowVCipher with default values.
        Sets up Linear Feedback Shift Registers (LFSR) and Finite State Machines (FSM) states.
        Initializes a list to store z values during the initialization phase.
        """
        self.A = [0]*16  # LFSR A: Array of 16 16-bit values
        self.B = [0]*16  # LFSR B: Array of 16 16-bit values
        self.R1 = [0]*4  # FSM R1: Array of 4 32-bit values
        self.R2 = [0]*4  # FSM R2: Array of 4 32-bit values
        self.R3 = [0]*4  # FSM R3: Array of 4 32-bit values
        self.init_z_values = []  # List to store z values during initialization

    def mul_x(self, v, c):
        """
        Multiply a 16-bit value by x in GF(2^16) with a given constant.
        :param v: 16-bit integer value.
        :param c: 16-bit constant used for reduction.
        :return: Result of multiplication in GF(2^16).
        """
        v &= 0xFFFF  # Ensure v is 16 bits
        if v & 0x8000:  # Check if the highest bit is set
            return ((v << 1) ^ c) & 0xFFFF  # Perform multiplication with reduction
        else:
            return (v << 1) & 0xFFFF  # Simple left shift if no reduction needed

    def mul_x_inv(self, v, d):
        """
        Multiply the inverse of x for a 16-bit value in GF(2^16) with a given constant.
        :param v: 16-bit integer value.
        :param d: 16-bit constant used for reduction.
        :return: Result of inverse multiplication in GF(2^16).
        """
        v &= 0xFFFF  # Ensure v is 16 bits
        if v & 0x0001:  # Check if the lowest bit is set
            return ((v >> 1) ^ d) & 0xFFFF  # Perform inverse multiplication with reduction
        else:
            return (v >> 1) & 0xFFFF  # Simple right shift if no reduction needed

    def permute_sigma(self, state):
        """
        Apply the Sigma permutation to the current state.
        Rearranges the bytes in the state according to the Sigma table.
        :param state: List of 16-bit integers representing the state.
        """
        tmp = [0]*16  # Temporary list to hold permuted values
        for i in range(16):
            index = self.Sigma[i]  # Get the permutation index from Sigma
            # Extract the byte from the state based on the index
            tmp[i] = (state[index >> 2] >> ((index & 3) * 8)) & 0xFF
        for i in range(4):
            # Combine four bytes into a 32-bit word in little-endian order
            state[i] = (tmp[4*i + 3] << 24) | (tmp[4*i + 2] << 16) | (tmp[4*i + 1] << 8) | tmp[4*i + 0]

    def aes_enc_round(self, state, roundKey):
        """
        Perform an AES encryption round on the FSM state using the provided round key.
        :param state: List of four 32-bit integers representing the FSM state.
        :param roundKey: List of four 32-bit integers representing the round key.
        :return: Updated FSM state after the AES round.
        """
        sb = [0]*16  # Substitute bytes array
        for i in range(4):
            for j in range(4):
                # Apply SBox substitution to each byte of the state
                sb[i*4 + j] = self.SBox[(state[i] >> (j*8)) & 0xFF]
        
        result = [0]*4  # Array to hold the result of the AES round
        for j in range(4):
            # Perform ShiftRows-like permutation on substituted bytes
            w = (
                (sb[(j*4 + 0) % 16] << 24) |
                (sb[(j*4 + 5) % 16] << 0) |
                (sb[(j*4 + 10) % 16] << 8) |
                (sb[(j*4 + 15) % 16] << 16)
            ) & 0xFFFFFFFF  # Combine bytes into a 32-bit word
            
            # Perform bitwise rotations and multiplications for MixColumns-like transformation
            t = ((w << 16) | (w >> 16)) & 0xFFFFFFFF  # Rotate left by 16 bits
            t ^= ((w << 1) & 0xFEFEFEFE)  # XOR with shifted word
            t ^= (((w >> 7) & 0x01010101) * 0x1B)  # Conditional XOR based on shifted bits
            t &= 0xFFFFFFFF  # Ensure t is 32 bits
            
            # Combine transformations with the round key
            result[j] = (roundKey[j] ^ w ^ t ^ ((t << 8) | (t >> 24))) & 0xFFFFFFFF
        
        return result  # Return the updated FSM state after the AES round

    def fsm_update(self):
        """
        Update the Finite State Machines (FSM) R1, R2, and R3 based on current states.
        This involves arithmetic and bitwise operations to transition the FSM states.
        """
        R1temp = self.R1[:]  # Create a copy of the current R1 state
        for i in range(4):
            # Combine two 16-bit A registers into a 32-bit value
            T2 = ((self.A[2*i + 1] << 16) | self.A[2*i]) & 0xFFFFFFFF
            # Update R1 by XORing with R3 and adding R2
            self.R1[i] = ((T2 ^ self.R3[i]) + self.R2[i]) & 0xFFFFFFFF
        self.permute_sigma(self.R1)  # Apply Sigma permutation to R1
        self.R3 = self.aes_enc_round(self.R2, [0]*4)  # Update R3 using AES encryption round on R2 with zero round key
        self.R2 = self.aes_enc_round(R1temp, [0]*4)  # Update R2 using AES encryption round on copied R1 with zero round key

    def lfsr_update(self):
        """
        Update the Linear Feedback Shift Registers (LFSR) A and B.
        Performs multiple iterations of feedback and shifting to maintain the cipher state.
        """
        for _ in range(8):  # Perform 8 iterations for thorough LFSR state update
            # Calculate the feedback value 'u' for LFSR A using multiplication and XOR operations
            u = self.mul_x(self.A[0], 0x990f) ^ self.A[1] ^ self.mul_x_inv(self.A[8], 0xcc87) ^ self.B[0]
            # Calculate the feedback value 'v' for LFSR B using multiplication and XOR operations
            v = self.mul_x(self.B[0], 0xc963) ^ self.B[3] ^ self.mul_x_inv(self.B[8], 0xe4b1) ^ self.A[0]
            # Shift the A register left by one and insert the new 'u' value
            self.A = self.A[1:] + [u & 0xFFFF]
            # Shift the B register left by one and insert the new 'v' value
            self.B = self.B[1:] + [v & 0xFFFF]

    def keystream(self):
        """
        Generate a 16-byte keystream block based on the current FSM and LFSR states.
        This is used for encrypting or decrypting data by XORing with plaintext or ciphertext.
        :return: List of 16 bytes representing the keystream block.
        """
        z = [0]*16  # Initialize a list to hold 16 bytes of keystream
        for i in range(4):
            # Combine two 16-bit B registers into a 32-bit value T1
            T1 = ((self.B[2*i + 9] << 16) | self.B[2*i + 8]) & 0xFFFFFFFF
            # Compute intermediate value 'v' by XORing T1 with R1 and adding R2
            v = ((T1 + self.R1[i]) ^ self.R2[i]) & 0xFFFFFFFF
            # Extract individual bytes from the 32-bit value 'v' in little-endian order
            z[i*4 + 0] = (v >> 0) & 0xFF
            z[i*4 + 1] = (v >> 8) & 0xFF
            z[i*4 + 2] = (v >> 16) & 0xFF
            z[i*4 + 3] = (v >> 24) & 0xFF
        self.fsm_update()  # Update FSM states after generating keystream
        self.lfsr_update()  # Update LFSR states after generating keystream
        return z  # Return the generated keystream block

    def keyiv_setup(self, key, iv, is_aead_mode=False):
        """
        Initialize the cipher with the provided key and initialization vector (IV).
        Sets up the LFSR A and B registers and initializes FSM states.
        :param key: Byte sequence representing the encryption key.
        :param iv: Byte sequence representing the initialization vector.
        :param is_aead_mode: Boolean flag indicating if AEAD mode is used.
        """
        for i in range(8):
            # Initialize the first 8 elements of LFSR A with IV bytes (little-endian)
            self.A[i] = ((iv[2*i + 1] << 8) | iv[2*i]) & 0xFFFF
            # Initialize the next 8 elements of LFSR A with key bytes (little-endian)
            self.A[i + 8] = ((key[2*i + 1] << 8) | key[2*i]) & 0xFFFF
            self.B[i] = 0x0000  # Initialize the first 8 elements of LFSR B to zero
            # Initialize the next 8 elements of LFSR B with key bytes (little-endian)
            self.B[i + 8] = ((key[2*i + 17] << 8) | key[2*i + 16]) & 0xFFFF
        
        if is_aead_mode:
            # If in AEAD mode, set specific initial values for LFSR B
            self.B[0] = 0x6C41
            self.B[1] = 0x7865
            self.B[2] = 0x6B45
            self.B[3] = 0x2064
            self.B[4] = 0x694A
            self.B[5] = 0x676E
            self.B[6] = 0x6854
            self.B[7] = 0x6D6F
        
        # Reset FSM states to zero
        self.R1 = [0]*4
        self.R2 = [0]*4
        self.R3 = [0]*4
        
        # Perform initialization by generating keystream and updating registers
        for i in range(16):
            z = self.keystream()  # Generate a keystream block
            self.init_z_values.append(z)  # Store the generated z values for initialization
            for j in range(8):
                # XOR the upper and lower bytes of z with LFSR A registers
                self.A[j + 8] ^= ((z[2*j + 1] << 8) | z[2*j]) & 0xFFFF
            if i == 14:
                for j in range(4):
                    # XOR the FSM R1 with parts of the key at round 14
                    self.R1[j] ^= ((key[4*j + 3] << 24) | (key[4*j + 2] << 16) | (key[4*j + 1] << 8) | key[4*j + 0]) & 0xFFFFFFFF
            if i == 15:
                for j in range(4):
                    # XOR the FSM R1 with parts of the key at round 15
                    self.R1[j] ^= ((key[4*j + 19] << 24) | (key[4*j + 18] << 16) | (key[4*j + 17] << 8) | key[4*j + 16]) & 0xFFFFFFFF

    def encrypt(self, plaintext):
        """
        Encrypt the provided plaintext using the generated keystream.
        :param plaintext: Byte sequence of plaintext to be encrypted.
        :return: Byte sequence of the resulting ciphertext.
        """
        ciphertext = bytearray()  # Initialize ciphertext as a mutable bytearray
        for i in range(0, len(plaintext), 16):  # Process plaintext in 16-byte blocks
            keystream_block = self.keystream()  # Generate a keystream block
            block = plaintext[i:i+16]  # Extract the current plaintext block
            for j in range(len(block)):  # XOR each byte of the block with the keystream
                ciphertext.append(block[j] ^ keystream_block[j])
        return bytes(ciphertext)  # Convert ciphertext to immutable bytes before returning
    
    def encrypt_hex(self, hex_input):
        """
        Encrypt a plaintext provided as a hexadecimal string.
        :param hex_input: Hexadecimal string representing the plaintext.
        :return: Byte sequence of the resulting ciphertext.
        """
        plaintext = bytes.fromhex(hex_input)  # Convert hex string to bytes
        ciphertext = bytearray()  # Initialize ciphertext as a mutable bytearray
        for i in range(0, len(plaintext), 16):  # Process plaintext in 16-byte blocks
            keystream_block = self.keystream()  # Generate a keystream block
            block = plaintext[i:i+16]  # Extract the current plaintext block
            for j in range(len(block)):  # XOR each byte of the block with the keystream
                ciphertext.append(block[j] ^ keystream_block[j])
        return bytes(ciphertext)  # Convert ciphertext to immutable bytes before returning

    def generate_keystream(self, length):
        """
        Generate a keystream of the specified length.
        :param length: Number of keystream bytes to generate.
        :return: Byte sequence of the generated keystream.
        """
        keystream_bytes = bytearray()  # Initialize keystream as a mutable bytearray
        for _ in range(0, length, 16):  # Generate keystream in 16-byte blocks
            keystream_block = self.keystream()  # Generate a keystream block
            keystream_bytes.extend(keystream_block)  # Append the keystream block to the bytearray
        return bytes(keystream_bytes[:length])  # Return the requested number of bytes as immutable bytes
