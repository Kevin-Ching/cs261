#include "native/examples/examples.h"
#include "my_utils.h"

using namespace std;
using namespace seal;

uint64_t vec_dot_product_ints(vector<uint64_t> vec1, vector<uint64_t> vec2, size_t length)
{
    uint64_t result = 0;
    for (size_t i = 0; i < length; i++)
    {
        result += vec1[i] * vec2[i];
    }
    return result;
}

Ciphertext enc_dot_product(Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, Ciphertext &encrypted1, const Ciphertext &encrypted2, size_t length)
{
    /* Multiply the two ciphertexts */
    Ciphertext product;
    evaluator.multiply(encrypted1, encrypted2, product);
    evaluator.relinearize_inplace(product, relin_keys);

    // cout << "whatup" << endl;
    /* Repeatedly rotate and add */
    for (size_t rotation_steps = length / 2; rotation_steps >= 1; rotation_steps /= 2)
    {
        // cout << rotation_steps << endl;
        Ciphertext product_rotated;
        evaluator.rotate_rows(product, rotation_steps, galois_keys, product_rotated);

        // cout << "whatup again" << endl;
        evaluator.add_inplace(product, product_rotated);
    }

    return product;
}

uint64_t dot_product_val_BFV(Decryptor &decryptor, BatchEncoder &batch_encoder, Ciphertext &encrypted)
{
    Plaintext plain_result;
    decryptor.decrypt(encrypted, plain_result);
    
    vector<uint64_t> pod_result;
    batch_encoder.decode(plain_result, pod_result);

    return pod_result[0];
}