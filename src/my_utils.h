#include "native/examples/examples.h"

using namespace std;
using namespace seal;

uint64_t vec_dot_product_ints(vector<uint64_t> vec1, vector<uint64_t> vec2, size_t length);

Ciphertext enc_dot_product_ints(Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, Ciphertext &encrypted1, const Ciphertext &encrypted2, size_t length);

uint64_t dot_product_val_BFV(Decryptor &decryptor, BatchEncoder &batch_encoder, Ciphertext &encrypted);

double vec_dot_product_floats(vector<double> vec1, vector<double> vec2, size_t length);

Ciphertext enc_dot_product_floats(Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, Ciphertext &encrypted1, const Ciphertext &encrypted2, size_t length);

double dot_product_val_CKKS(Decryptor &decryptor, CKKSEncoder &encoder, Ciphertext &encrypted);