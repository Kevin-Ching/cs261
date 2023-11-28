#include "native/examples/examples.h"
#include "my_utils.h"

using namespace std;
using namespace seal;

void test_integer_dot_product()
{
    const size_t LENGTH = 1024;

    print_example_banner("Test: Integer Dot Product");

    /* Setting parameters */
    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

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

    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    /* Print "length" of matrices */
    cout << "Matrix/vector lengths: " << LENGTH << endl;

    /* Upper bound on matrix values */
    srand(time(NULL));
    uint64_t upper_bound = parms.plain_modulus().value();

    /* Creating matrix 1 */
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    for (size_t i = 0; i < LENGTH; i++)
    {
        pod_matrix[i] = rand() % upper_bound;
    }

    cout << "Input plaintext matrix:" << endl;
    print_matrix(pod_matrix, row_size);

    /* Encoding and encrypting matrix 1 */
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "Encode and encrypt." << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "    + Noise budget in encrypted_matrix: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits"
         << endl;

    /* Creating matrix 2 */
    vector<uint64_t> pod_matrix2(slot_count, 0ULL);
    for (size_t i = 0; i < LENGTH; i++)
    {
        pod_matrix2[i] = rand() % upper_bound;
    }

    cout << "Second input plaintext matrix:" << endl;
    print_matrix(pod_matrix2, row_size);

    /* Encoding and encrypting matrix 2 */
    Plaintext plain_matrix2;
    print_line(__LINE__);
    cout << "Encode and encrypt." << endl;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    Ciphertext encrypted_matrix2;
    encryptor.encrypt(plain_matrix2, encrypted_matrix2);
    cout << "    + Noise budget in encrypted_matrix: " << decryptor.invariant_noise_budget(encrypted_matrix2) << " bits"
         << endl;

    /* Printing true result (modulus an upper bound on values (plain_modulus))*/
    print_line(__LINE__);
    cout << "Computing plaintext dot product." << endl;
    uint64_t true_result = vec_int_dot_product(pod_matrix, pod_matrix2, LENGTH) % upper_bound;
    cout << "   + Expected result: " << true_result << endl;

    /* Evaluating encrypted dot product and printing result */
    print_line(__LINE__);
    cout << "Evaluating encrypted dot product." << endl;
    Ciphertext product = BFV_dot_product(evaluator, relin_keys, galois_keys, encrypted_matrix, encrypted_matrix2, LENGTH);
    uint64_t result = BFV_result(decryptor, batch_encoder, product);
    cout << "   + Computed result: " << result << endl;

    /* Print whether the result is correct */
    print_line(__LINE__);
    string correctness = "correct";
    if (true_result != result)
    {
        correctness = "incorrect";
    }
    cout << "The result is: " << correctness << endl;
}