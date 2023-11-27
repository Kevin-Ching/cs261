#include "native/examples/examples.h"

using namespace std;
using namespace seal;

uint64_t vec_dot_product_ints(vector<uint64_t> vec1, vector<uint64_t> vec2, size_t length);

Ciphertext enc_dot_product(Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, Ciphertext &encrypted1, const Ciphertext &encrypted2, size_t length);

uint64_t dot_product_val_BFV(Decryptor &decryptor, BatchEncoder &batch_encoder, Ciphertext &encrypted);