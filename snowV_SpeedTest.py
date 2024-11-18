# snowvSpeedTest.py

import time
import os
import statistics  # Import statistics module for computing mean and standard deviation
from snowV import SnowVCipher

def generate_random_bytes(size_in_bytes):
    """
    Generates random bytes of the specified size.

    :param size_in_bytes: The number of bytes to generate.
    :return: A bytes object containing random bytes.
    """
    return os.urandom(size_in_bytes)

def format_time(elapsed_time):
    """
    Formats the elapsed time into milliseconds with three decimal places.

    :param elapsed_time: Time elapsed in seconds.
    :return: A string representing the time in milliseconds.
    """
    return f"{elapsed_time * 1000:.3f} ms"

def main():
    # Initialize SNOW-V instance
    cipher = SnowVCipher()

    # Define fixed key and IV for consistency across tests
    key_hex = (
        '000102030405060708090a0b0c0d0e0f'
        '101112131415161718191a1b1c1d1e1f'
    )  # 32 bytes key (256 bits)
    iv_hex = '202122232425262728292a2b2c2d2e2f'  # 16 bytes IV (128 bits)

    # Convert hex strings to bytes
    key = hexstr_to_bytes(key_hex)
    iv = hexstr_to_bytes(iv_hex)

    # Setup key and IV in the cipher
    cipher.keyiv_setup(list(key), list(iv))

    # Define plaintext sizes in bits and their corresponding byte sizes
    plaintext_sizes = {
        '256 bits': 32,    # 32 bytes
        '1024 bits': 128,  # 128 bytes
        '8192 bits': 1024  # 1024 bytes
    }

    # Number of iterations for each test to obtain average time
    iterations = 1000

    print("SNOW-V Speed Test")
    print("================\n")
    print(f"Number of Iterations per Test: {iterations}\n")
    print(f"Keys and IV are fixed for all tests.\n")

    for size_label, size_bytes in plaintext_sizes.items():
        # Generate random plaintext of the specified size
        plaintext = generate_random_bytes(size_bytes)

        # Warm-up run (optional but can help with more consistent timing)
        ciphertext = cipher.encrypt(plaintext)

        # List to store individual encryption times
        encryption_times = []

        # Start timing for each encryption operation
        for _ in range(iterations):
            start_time = time.perf_counter()  # Start time for this iteration
            ciphertext = cipher.encrypt(plaintext)  # Perform encryption
            end_time = time.perf_counter()  # End time for this iteration
            iteration_time = end_time - start_time  # Calculate elapsed time
            encryption_times.append(iteration_time)  # Store the time

        # Calculate statistics
        average_time = statistics.mean(encryption_times)  # Average encryption time
        min_time = min(encryption_times)  # Minimum encryption time using built-in min
        max_time = max(encryption_times)  # Maximum encryption time using built-in max
        std_dev = statistics.stdev(encryption_times)  # Standard deviation

        # Print results
        print(f"Plaintext Size: {size_label} ({size_bytes} bytes)")
        print(f"Average Encryption Time over {iterations} iterations: {format_time(average_time)}")
        print(f"Minimum Encryption Time: {format_time(min_time)}")
        print(f"Maximum Encryption Time: {format_time(max_time)}")
        print(f"Standard Deviation: {format_time(std_dev)}\n")

def hexstr_to_bytes(hexstr):
    """
    Converts a hexadecimal string to bytes.

    :param hexstr: A string containing hexadecimal characters, possibly separated by spaces.
    :return: A bytes object.
    """
    return bytes.fromhex(hexstr.replace(" ", "").replace("\n", ""))

if __name__ == "__main__":
    main()
