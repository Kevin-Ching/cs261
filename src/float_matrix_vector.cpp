#include "native/examples/examples.h"
#include "my_utils.h"

using namespace std;
using namespace seal;

void test_float_matrix_vector_product()
{
    const size_t LENGTH = 1024;
    const double UPPER_BOUND = 1000000;
    const double LOWER_BOUND = -UPPER_BOUND;
    const double NUM_ROWS = 8;

    print_example_banner("Test: Float Matrix Vector Product");

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

    /* Print length of vectors */
    cout << "Vector lengths: " << LENGTH << endl;

    /* Print number of rows */
    cout << "Number of rows: " << NUM_ROWS << endl;

    /* Setting up PRNG for doubles */
    srand(time(NULL));
    uniform_real_distribution<double> unif(LOWER_BOUND, UPPER_BOUND);
    random_device rd;
    mt19937 gen(rd());

    /* Creating matrix */
    vector<vector<double>> matrix(NUM_ROWS, vector<double>(slot_count, 0ULL));
    for (size_t i = 0; i < NUM_ROWS; i++)
    {
        for (size_t j = 0; j < LENGTH; j++)
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

    /* Creating vector */
    vector<double> vec(slot_count, 0ULL);
    for (size_t i = 0; i < LENGTH; i++)
    {
        vec[i] = unif(gen);
    }

    cout << "Input plaintext vector:" << endl;
    print_vector(vec, 3, 7);

    /* Encoding and encrypting vector */
    print_line(__LINE__);
    cout << "Encode and encrypt." << endl;
    encoder.encode(vec, scale, plain_vector);
    Ciphertext encrypted_vector;
    encryptor.encrypt(plain_vector, encrypted_vector);

    /* Printing true results */
    print_line(__LINE__);
    cout << "Computing plaintext matrix vector product." << endl;
    vector<double> true_results = matrix_vec_product_floats(matrix, vec, LENGTH);
    cout << "   + Expected result: " << endl;
    print_vector(true_results, 3, 7);

    /* Evaluating encrypted matrix vector product and printing result */
    print_line(__LINE__);
    cout << "Evaluating encrypted matrix vector product." << endl;
    vector<Ciphertext> product_vector = enc_matrix_vector_product_floats(evaluator, relin_keys, galois_keys, encrypted_matrix, encrypted_vector, LENGTH);
    vector<double> results = matrix_vector_product_vals(decryptor, encoder, product_vector);
    cout << "   + Computed result: " << endl;
    print_vector(results, 3, 7);

    /* Print the absolute deviations from the true results */
    print_line(__LINE__);
    cout << "The absolute deviations from the true results are: " << endl;
    vector<double> deviations(NUM_ROWS);
    for (size_t i = 0; i < NUM_ROWS; i++)
    {
        deviations[i] = abs(true_results[i] - results[i]);
    }
    print_vector(deviations, 3, 7);
}