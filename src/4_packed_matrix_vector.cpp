#include "native/examples/examples.h"
#include "my_utils.h"

using namespace std;
using namespace seal;

void test_packed_matrix_vector_product()
{
    /* Parameters for the test */
    const size_t DIMENSION = 128;
    const double UPPER_BOUND = 1000000;
    const double LOWER_BOUND = -UPPER_BOUND;
    const double NUM_ROWS = 32;
    const double TOLERANCE = 0.05;

    print_example_banner("Test: Packed Float Matrix Vector Product");

    /* Setting parameters */
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    /* Setting scale */
    double scale = pow(2.0, 40);

    /* Creating context */
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    /* Verification that batching is enabled */
    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    /* Setting up keys and object instances */
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    /* Print dimension of vectors */
    cout << "Dimension of vectors: " << DIMENSION << endl;

    /* Print number of rows */
    cout << "Number of rows: " << NUM_ROWS << endl;

    /* Print total number of unpacked vectors */
    size_t num_vecs_per_row = slot_count / DIMENSION;
    size_t total_num_vecs = num_vecs_per_row * NUM_ROWS;
    cout << "Total number of unpacked vectors: " << total_num_vecs << endl;

    /* Setting up PRNG for doubles */
    uniform_real_distribution<double> unif(LOWER_BOUND, UPPER_BOUND);
    random_device rd;
    mt19937 gen(rd());

    /* Creating matrix */
    vector<vector<double>> matrix(NUM_ROWS, vector<double>(slot_count, 0ULL));
    for (size_t i = 0; i < NUM_ROWS; i++)
    {
        for (size_t j = 0; j < slot_count; j++)
        {
            matrix[i][j] = unif(gen);
        }
    }

    /* Print out the first few row vectors */
    for (size_t i = 0; i < 3; i++)
    {
        cout << "Matrix row vector #" << i << ":" << endl;
        print_vector(matrix[i], 3, 7);
    }

    /* Encoding and encrypting matrix */
    Plaintext plain_vector;
    print_line(__LINE__);
    cout << "Encode and encrypt matrix." << endl;

    vector<Ciphertext> encrypted_matrix(NUM_ROWS);
    for (size_t i = 0; i < NUM_ROWS; i++)
    {
        encoder.encode(matrix[i], scale, plain_vector);
        Ciphertext encrypted_vector;
        encryptor.encrypt(plain_vector, encrypted_vector);
        encrypted_matrix[i] = encrypted_vector;
    }

    /* Creating duplicated vector */
    vector<double> duplicated_vec(slot_count, 0ULL);
    for (size_t i = 0; i < DIMENSION; i++)
    {
        double randVal = unif(gen);
        for (size_t j = i; j < slot_count; j += DIMENSION)
        {
            duplicated_vec[j] = randVal;
        }
    }

    cout << "Input plaintext vector:" << endl;
    print_vector(duplicated_vec, 3, 7);

    /* Encoding and encrypting vector */
    print_line(__LINE__);
    cout << "Encode and encrypt." << endl;
    encoder.encode(duplicated_vec, scale, plain_vector);
    Ciphertext encrypted_vector;
    encryptor.encrypt(plain_vector, encrypted_vector);

    /* Printing true results */
    print_line(__LINE__);
    cout << "Computing plaintext matrix vector product." << endl;
    vector<double> true_results = packed_matrix_vec_product(matrix, duplicated_vec, DIMENSION);
    cout << "   + Expected result: " << endl;
    print_vector(true_results, 3, 7);

    /* Evaluating encrypted matrix vector product and printing result */
    print_line(__LINE__);
    cout << "Evaluating encrypted matrix vector product." << endl;
    vector<Ciphertext> product_vector = CKKS_matrix_vector_product(evaluator, relin_keys, galois_keys, encrypted_matrix, encrypted_vector, DIMENSION);
    vector<double> results = packed_CKKS_results(decryptor, encoder, product_vector, DIMENSION, num_vecs_per_row);
    cout << "   + Computed result: " << endl;
    print_vector(results, 3, 7);

    /* Print the absolute deviations from the true results */
    print_line(__LINE__);
    cout << "The absolute deviations from the true results are: " << endl;
    vector<double> deviations(NUM_ROWS);
    bool all_within_tol = true;
    for (size_t i = 0; i < NUM_ROWS; i++)
    {
        double deviation = abs(true_results[i] - results[i]);
        deviations[i] = deviation;
        if (deviation >= TOLERANCE)
        {
            all_within_tol = false;
        }
    }
    print_vector(deviations, 3, 7);

    /* Checking that all deviations are within the tolerance */
    print_line(__LINE__);
    cout << "The tolerance is: " << TOLERANCE << endl;
    cout << "All deviations are within the tolerance: " << all_within_tol << endl << endl;
}