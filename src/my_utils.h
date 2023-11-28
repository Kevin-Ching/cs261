#include "native/examples/examples.h"

using namespace std;
using namespace seal;

uint64_t vec_int_dot_product(vector<uint64_t> vec1, vector<uint64_t> vec2, size_t length);

Ciphertext BFV_dot_product(
    Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, 
    Ciphertext &encrypted1, Ciphertext &encrypted2, size_t length
);

uint64_t BFV_result(Decryptor &decryptor, BatchEncoder &batch_encoder, Ciphertext &encrypted);

double vec_float_dot_product(vector<double> vec1, vector<double> vec2, size_t length);

Ciphertext CKKS_dot_product(
    Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, 
    Ciphertext &encrypted1, Ciphertext &encrypted2, size_t length
);

double CKKS_result(Decryptor &decryptor, CKKSEncoder &encoder, Ciphertext &encrypted);

vector<double> matrix_vec_product(vector<vector<double>> matrix, vector<double> vec, size_t length);

vector<Ciphertext> CKKS_matrix_vector_product(
    Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, 
    vector<Ciphertext> &encrypted_matrix, Ciphertext &encrypted_vector, size_t length
);

vector<double> CKKS_results(Decryptor &decryptor, CKKSEncoder &encoder, vector<Ciphertext> &vector_of_encrypted);