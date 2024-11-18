# SNOW-V Cipher

First Ever Implementation of SnowV in python on Github
An AES-based stream cipher designed for high-speed encryption in virtualized environments, suitable for 5G mobile communication systems. SNOW-V is a revision of the SNOW 3G architecture, optimized to leverage modern CPU features like AES-NI and SIMD instructions for enhanced performance.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Implementation Details](#implementation-details)
- [Installation](#installation)
- [Usage](#usage)
  - [Running the Python Implementation](#running-the-python-implementation)
  - [Compiling and Running the C Implementation](#compiling-and-running-the-c-implementation)
- [Performance](#performance)
- [Project Report](#project-report)
- [Contributing](#contributing)
- [License](#license)
- [References](#references)

## Introduction

SNOW-V is a member of the SNOW family of stream ciphers, designed to meet the industry's demand for very high-speed encryption in virtualized environments, such as those expected in future 5G mobile communication systems. By revising the SNOW 3G architecture, SNOW-V aligns better with vectorized implementations, making full use of AES-NI and SIMD instructions to achieve higher throughput.

## Features

- **High-Speed Encryption**: Optimized for software implementations, significantly faster than AES-256.
- **Software Optimization**: Utilizes AES-NI and SIMD instructions for enhanced performance on modern CPUs.
- **Enhanced Security**: Incorporates an increased state size with 128-bit registers in the FSM.
- **Improved Components**:
  - **LFSR**: Operates at eight times the speed of the FSM for efficiency.
  - **FSM Update**: Uses the full AES encryption round function to strengthen cryptographic properties.
  - **Initialization Phase**: Includes masking with key bits at the end for added security.

## Implementation Details

This repository contains both Python and C implementations of the SNOW-V cipher:

- **Python Implementation**: Provides a clear and educational representation of the algorithm, suitable for understanding the cipher's operation.
- **C Implementation**: Optimized for performance, capable of utilizing hardware acceleration features for high-speed encryption.

## Installation

### Prerequisites

- **Python Implementation**:
  - Python 3.x
- **C Implementation**:
  - GCC or another C compiler supporting C99 standard.
  - CPU supporting AES-NI and SIMD instructions for optimal performance.

### Cloning the Repository

```bash
git clone https://github.com/your_username/snowv-cipher.git
cd snowv-cipher
```

## Usage

### Running the Python Implementation

1. **Navigate to the Python Directory**:

   ```bash
   cd python
   ```

2. **Install Required Packages** (if any):

   The Python implementation may require certain packages. Install them using:

   ```bash
   pip install -r requirements.txt
   ```

   *Note: The `requirements.txt` file should list any dependencies. If there are none, this step can be skipped.*

3. **Run the SNOW-V Cipher Script**:

   ```bash
   python SnowVCipher.py
   ```

   The script includes test vectors and can be modified to encrypt/decrypt custom data.

### Compiling and Running the C Implementation

1. **Navigate to the C Directory**:

   ```bash
   cd c
   ```

2. **Compile the SNOW-V Cipher Program**:

   ```bash
   gcc -o snowv_cipher snowv_cipher.c -O3 -maes -msse4.1
   ```

   - The `-O3` flag enables high-level optimizations.
   - The `-maes` and `-msse4.1` flags enable the use of AES-NI and SSE4.1 instructions.

3. **Run the SNOW-V Cipher Program**:

   ```bash
   ./snowv_cipher
   ```

   The program can be modified to encrypt/decrypt custom data and measure performance.

## Performance

SNOW-V is designed to achieve high-speed encryption suitable for 5G systems. When compiled with optimizations and hardware acceleration enabled, the C implementation can significantly outperform traditional ciphers like AES-256.

Performance highlights:

- **Encryption Speed**: Achieves encryption times suitable for high-throughput applications.
- **Scalability**: Demonstrates consistent performance scaling with increasing data sizes.

Refer to the [Project Report](#project-report) for detailed performance analysis and benchmarking results.

## Project Report

A comprehensive project report is included in the `report` directory, covering:

- Detailed descriptions of the SNOW-V cipher's design and implementation.
- In-depth explanations of each function in the code.
- Performance comparison between Python and C implementations.
- Analysis and conclusions based on the results.

Access the report in PDF format: [Project_Report.pdf](report/Project_Report.pdf)

## Contributing

Contributions to the SNOW-V cipher implementation are welcome. If you have suggestions for improvements, optimizations, or bug fixes, please follow these steps:

1. **Fork the Repository**:

   Click the "Fork" button at the top right corner of this page to create a copy of the repository in your own GitHub account.

2. **Clone Your Fork**:

   ```bash
   git clone https://github.com/your_username/snowv-cipher.git
   cd snowv-cipher
   ```

3. **Create a New Branch**:

   ```bash
   git checkout -b feature/YourFeatureName
   ```

4. **Make Changes**:

   Implement your changes or additions.

5. **Commit Your Changes**:

   ```bash
   git commit -am 'Add new feature: YourFeatureName'
   ```

6. **Push to Your Fork**:

   ```bash
   git push origin feature/YourFeatureName
   ```

7. **Open a Pull Request**:

   Go to the original repository and open a pull request from your new branch.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## References

1. **SNOW-V Cipher Original Paper**:
   - Johansson, T., Maximov, A., & Meier, W. (2018). SNOW-V: A New SNOW Stream Cipher with Improved Security. *IACR Cryptology ePrint Archive*, 2018/1143. [Link](https://eprint.iacr.org/2018/1143.pdf)

---

*Disclaimer: This implementation is provided for educational purposes only and should not be used in production environments without proper security evaluations.*
