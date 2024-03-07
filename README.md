# Dot Products with Homomorphic Encryption

A naive implementation of a system that performs similarity search over encrypted embeddings involves using homomorphic encryption. 
A simple measure of embedding similarity is a vector dot product. 
This repo was created to test an implementation of taking dot products over encrypted embeddings as a performance baseline for a prototype system. 
In particular, I used the [Microsoft SEAL HE library](https://github.com/microsoft/SEAL) for implementation, as well as for inspiration for the overall project structure. 

## Prerequisites

- Linux environment

As this project was made with WSL, the following instructions assume a Linux environment. 
If you don't already have them, you can install essential build tools and CMake as follows: 
```bash
sudo apt-get update
sudo apt-get install build-essential
sudo apt-get install cmake
```

## Getting Started

1. Clone the repository.
2. Navigate to the project directory.
3. Clone the [Microsoft SEAL](https://github.com/microsoft/SEAL) repository into this directory as a subdirectory.

## Configure and Compile

Configure and compile the project into the `build` directory as follows: 
```bash
cmake -S . -B build
cmake --build build
```

## Run Tests

The tests can now be run with: 
```bash
./build/tests
```

## Tests

The tests are divided into several source files in `src` as follows: 

| Source Files                 | Description                  |
|------------------------------|------------------------------|
| `tests.cpp`                  | The test runner application  |
| `1_integer_dot_product.cpp`  | `1. Integer Dot Product`     |
| `2_float_dot_product.cpp`    | `2. Float Dot Product`       |
| `3_float_matrix_vector.cpp`  | `3. Float Matrix Vector`     |
| `4_packed_matrix_vector.cpp` | `4. Packed Matrix Vector`    |
| `5_timed_packed_products.cpp`| `5. Timed Packed Products`   |

Each test source file has parameters that can be changed, under the comment `/* Parameters for the test */`. 

Test 5 has additional parameters for the timing portion, under the comment `/* Change these input parameters */` on line 177. 

## Algorithm

The operations necessary for a dot product are element-wise multiplication and the means to compute an aggregated sum. 
Homomorphic encryption enables these operations with encrypted embeddings. 
Since we are working with ciphertexts, we cannot sum the entries of a vector by retrieving them individually. 
Cyclical rotation of vectors makes summation feasible.

To compute a dot product with homomorphic encryption, two $N$-dimensional ciphertexts are multiplied element-wise. 
Then, this new product vector is rotated $N/2$ steps and added element-wise to itself. 
Now, we effectively have a $N/2$ length ciphertext we would like to aggregate.
Thus, we repeatedly rotate and add, halving the number of steps rotated in each iteration. 
The number of iterations is therefore $log_2(N)$. 
Each entry of the resulting ciphertext will hold the full sum: the resulting dot product.

The duplication of the result in the final ciphertext seems like a waste. 
The nature of this algorithm allows for the packing of multiple embeddings into one ciphertext. 
If $M$ embeddings fit into a ciphertext, every $M$ th entry of the resulting ciphertext will hold the value of a dot product. 
The $i$ th dot product will be in the $(i ∗ N)$ th slot, with $i$ and the ciphertext indices zero-indexed.

### Memory Optimization

For the sake of memory, the timed test (Test 5) can be run with one randomly generated dataset vector in lieu of an entire database, which is computed against the same number of times as the dataset size. 
This is set with the `ONE_ROW_MATRIX` parameter at the top of the source file `src/5_timed_packed_products.cpp`. 
