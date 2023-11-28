#include "native/examples/examples.h"
#include "my_utils.h"

using namespace std;
using namespace seal;


/* Helper functions for integer dot products */
uint64_t vec_int_dot_product(vector<uint64_t> vec1, vector<uint64_t> vec2, size_t dimension)
{
    uint64_t result = 0;
    for (size_t i = 0; i < dimension; i++)
    {
        result += vec1[i] * vec2[i];
    }
    return result;
}

Ciphertext BFV_dot_product(
    Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, 
    Ciphertext &encrypted1, Ciphertext &encrypted2, size_t dimension
)
{
    /* Multiply the two ciphertexts */
    Ciphertext product;
    evaluator.multiply(encrypted1, encrypted2, product);
    evaluator.relinearize_inplace(product, relin_keys);

    /* Repeatedly rotate and add */
    for (size_t rotation_steps = dimension / 2; rotation_steps >= 1; rotation_steps /= 2)
    {
        Ciphertext product_rotated;
        evaluator.rotate_rows(product, rotation_steps, galois_keys, product_rotated);

        evaluator.add_inplace(product, product_rotated);
    }

    return product;
}

uint64_t BFV_result(Decryptor &decryptor, BatchEncoder &batch_encoder, Ciphertext &encrypted)
{
    Plaintext plain_result;
    decryptor.decrypt(encrypted, plain_result);
    
    vector<uint64_t> pod_result;
    batch_encoder.decode(plain_result, pod_result);

    return pod_result[0];
}

/* Helper functions for float dot products */
double vec_float_dot_product(vector<double> vec1, vector<double> vec2, size_t dimension)
{
    double result = 0;
    for (size_t i = 0; i < dimension; i++)
    {
        result += vec1[i] * vec2[i];
    }
    return result;
}

Ciphertext CKKS_dot_product(
    Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, 
    Ciphertext &encrypted1, Ciphertext &encrypted2, size_t dimension
)
{
    /* Multiply the two ciphertexts */
    Ciphertext product;
    evaluator.multiply(encrypted1, encrypted2, product);
    evaluator.relinearize_inplace(product, relin_keys);
    evaluator.rescale_to_next_inplace(product);

    /* Repeatedly rotate and add */
    for (size_t rotation_steps = dimension / 2; rotation_steps >= 1; rotation_steps /= 2)
    {
        Ciphertext product_rotated;
        evaluator.rotate_vector(product, rotation_steps, galois_keys, product_rotated);

        evaluator.add_inplace(product, product_rotated);
    }

    return product;
}

double CKKS_result(Decryptor &decryptor, CKKSEncoder &encoder, Ciphertext &encrypted)
{
    Plaintext plain_result;
    decryptor.decrypt(encrypted, plain_result);
    
    vector<double> vec_result;
    encoder.decode(plain_result, vec_result);

    return vec_result[0];
}

/* Helper functions for matrix vector float products */
vector<double> matrix_vec_product(vector<vector<double>> matrix, vector<double> vec, size_t dimension)
{
    vector<double> results(matrix.size());
    for (size_t i = 0; i < matrix.size(); i++)
    {
        vector<double> other_vec = matrix[i];
        results[i] = vec_float_dot_product(other_vec, vec, dimension);
    }
    return results;
}

vector<Ciphertext> CKKS_matrix_vector_product(
    Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys, 
    vector<Ciphertext> &encrypted_matrix, Ciphertext &encrypted_vector, size_t dimension
)
{
    vector<Ciphertext> product_vector(encrypted_matrix.size());
    for (size_t i = 0; i < encrypted_matrix.size(); i++)
    {
        Ciphertext other_encrypted_vector = encrypted_matrix[i];
        product_vector[i] = CKKS_dot_product(evaluator, relin_keys, galois_keys, other_encrypted_vector, encrypted_vector, dimension);
    }
    return product_vector;
}

vector<double> CKKS_results(Decryptor &decryptor, CKKSEncoder &encoder, vector<Ciphertext> &vector_of_encrypted)
{
    vector<double> results(vector_of_encrypted.size());
    for (size_t i = 0; i < vector_of_encrypted.size(); i++)
    {
        Ciphertext encrypted = vector_of_encrypted[i];
        results[i] = CKKS_result(decryptor, encoder, encrypted);
    }
    return results;
}


/* Helper functions for matrix vector float products with packed vectors */
vector<double> packed_vec_float_dot_product(vector<double> packed_vec, vector<double> duplicated_vec, size_t dimension)
{
    size_t num_vecs = packed_vec.size() / dimension;
    vector<double> results(num_vecs);
    for (size_t i = 0; i < num_vecs; i++)
    {
        vector<double> curr_vec(packed_vec.begin() + i*dimension, packed_vec.begin() + (i+1)*dimension);
        results[i] = vec_float_dot_product(curr_vec, duplicated_vec, dimension);
    }
    return results;
}

vector<double> packed_CKKS_result(Decryptor &decryptor, CKKSEncoder &encoder, Ciphertext &encrypted, size_t dimension)
{
    Plaintext plain_result;
    decryptor.decrypt(encrypted, plain_result);
    
    vector<double> vec_result;
    encoder.decode(plain_result, vec_result);

    size_t num_vecs = vec_result.size() / dimension;
    vector<double> results(num_vecs);
    for (size_t i = 0; i < num_vecs; i++)
    {
        results[i] = vec_result[i * dimension];
    }

    return results;
}

vector<double> packed_matrix_vec_product(vector<vector<double>> packed_matrix, vector<double> duplicated_vec, size_t dimension)
{
    size_t num_vecs_per_row = packed_matrix[0].size() / dimension;
    vector<double> results(packed_matrix.size() * num_vecs_per_row);
    for (size_t row_num = 0; row_num < packed_matrix.size(); row_num++)
    {
        vector<double> curr_row = packed_matrix[row_num];
        vector<double> dot_products = packed_vec_float_dot_product(curr_row, duplicated_vec, dimension);
        for (size_t j = 0; j < num_vecs_per_row; j++)
        {
            results[row_num*num_vecs_per_row + j] = dot_products[j];
        }
    }
    return results;
}

vector<double> packed_CKKS_results(
    Decryptor &decryptor, CKKSEncoder &encoder, vector<Ciphertext> &vector_of_encrypted, 
    size_t dimension, size_t num_vecs_per_row
)
{
    vector<double> results(vector_of_encrypted.size() * num_vecs_per_row);
    for (size_t row_num = 0; row_num < vector_of_encrypted.size(); row_num++)
    {
        Ciphertext encrypted = vector_of_encrypted[row_num];
        vector<double> dot_products = packed_CKKS_result(decryptor, encoder, encrypted, dimension);
        for (size_t j = 0; j < num_vecs_per_row; j++)
        {
            results[row_num*num_vecs_per_row + j] = dot_products[j];
        }
    }
    return results;
}