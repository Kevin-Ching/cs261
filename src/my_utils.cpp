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

Ciphertext enc_dot_product_ints(
    Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, 
    Ciphertext &encrypted1, Ciphertext &encrypted2, size_t length
)
{
    /* Multiply the two ciphertexts */
    Ciphertext product;
    evaluator.multiply(encrypted1, encrypted2, product);
    evaluator.relinearize_inplace(product, relin_keys);

    /* Repeatedly rotate and add */
    for (size_t rotation_steps = length / 2; rotation_steps >= 1; rotation_steps /= 2)
    {
        Ciphertext product_rotated;
        evaluator.rotate_rows(product, rotation_steps, galois_keys, product_rotated);

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

double vec_dot_product_floats(vector<double> vec1, vector<double> vec2, size_t length)
{
    double result = 0;
    for (size_t i = 0; i < length; i++)
    {
        result += vec1[i] * vec2[i];
    }
    return result;
}

Ciphertext enc_dot_product_floats(
    Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, 
    Ciphertext &encrypted1, Ciphertext &encrypted2, size_t length
)
{
    /* Multiply the two ciphertexts */
    Ciphertext product;
    evaluator.multiply(encrypted1, encrypted2, product);
    evaluator.relinearize_inplace(product, relin_keys);
    evaluator.rescale_to_next_inplace(product);

    // cout << "whatup" << endl;
    /* Repeatedly rotate and add */
    for (size_t rotation_steps = length / 2; rotation_steps >= 1; rotation_steps /= 2)
    {
        // cout << rotation_steps << endl;
        Ciphertext product_rotated;
        evaluator.rotate_vector(product, rotation_steps, galois_keys, product_rotated);

        // cout << "whatup again" << endl;
        evaluator.add_inplace(product, product_rotated);
    }

    return product;
}

double dot_product_val_CKKS(Decryptor &decryptor, CKKSEncoder &encoder, Ciphertext &encrypted)
{
    Plaintext plain_result;
    decryptor.decrypt(encrypted, plain_result);
    
    vector<double> vec_result;
    encoder.decode(plain_result, vec_result);

    return vec_result[0];
}

vector<double> matrix_vec_product_floats(vector<vector<double>> matrix, vector<double> vec, size_t length)
{
    vector<double> results(matrix.size());
    for (size_t i = 0; i < matrix.size(); i++)
    {
        vector<double> other_vec = matrix[i];
        results[i] = vec_dot_product_floats(other_vec, vec, length);
    }
    return results;
}

vector<Ciphertext> enc_matrix_vector_product_floats(
    Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, 
    vector<Ciphertext> &encrypted_matrix, Ciphertext &encrypted_vector, size_t length
)
{
    vector<Ciphertext> product_vector(encrypted_matrix.size());
    for (size_t i = 0; i < encrypted_matrix.size(); i++)
    {
        Ciphertext other_encrypted_vector = encrypted_matrix[i];
        product_vector[i] = enc_dot_product_floats(evaluator, relin_keys, galois_keys, other_encrypted_vector, encrypted_vector, length);
    }
    return product_vector;
}

vector<double> matrix_vector_product_vals(Decryptor &decryptor, CKKSEncoder &encoder, vector<Ciphertext> &vector_of_encrypted)
{
    vector<double> results(vector_of_encrypted.size());
    for (size_t i = 0; i < vector_of_encrypted.size(); i++)
    {
        Ciphertext encrypted = vector_of_encrypted[i];
        results[i] = dot_product_val_CKKS(decryptor, encoder, encrypted);
    }
    return results;
}