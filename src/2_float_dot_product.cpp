#include "native/examples/examples.h"
#include "my_utils.h"

using namespace std;
using namespace seal;

void test_float_dot_product()
{
    /* Parameters for the test */
    const size_t DIMENSION = 1024;
    const double UPPER_BOUND = 1000000;
    const double LOWER_BOUND = -UPPER_BOUND;
    const double TOLERANCE = 0.05;

    print_example_banner("Test: Float Dot Product");

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

    /* Setting up PRNG for doubles */
    uniform_real_distribution<double> unif(LOWER_BOUND, UPPER_BOUND);
    random_device rd;
    mt19937 gen(rd());

    /* Creating vector 1 */
    vector<double> vec(slot_count, 0ULL);
    for (size_t i = 0; i < DIMENSION; i++)
    {
        vec[i] = unif(gen);
    }

    cout << "Input plaintext vector:" << endl;
    print_vector(vec, 3, 7);

    /* Encoding and encrypting vector 1 */
    Plaintext plain_vector;
    print_line(__LINE__);
    cout << "Encode and encrypt." << endl;
    encoder.encode(vec, scale, plain_vector);
    Ciphertext encrypted_vector;
    encryptor.encrypt(plain_vector, encrypted_vector);

    /* Creating vector 2 */
    vector<double> vec2(slot_count, 0ULL);
    for (size_t i = 0; i < DIMENSION; i++)
    {
        vec2[i] = unif(gen);
    }

    cout << "Second input plaintext vector:" << endl;
    print_vector(vec2, 3, 7);

    /* Encoding and encrypting vector 2 */
    Plaintext plain_vector2;
    print_line(__LINE__);
    cout << "Encode and encrypt." << endl;
    encoder.encode(vec2, scale, plain_vector2);
    Ciphertext encrypted_vector2;
    encryptor.encrypt(plain_vector2, encrypted_vector2);

    /* Printing true result */
    print_line(__LINE__);
    cout << "Computing plaintext dot product." << endl;
    double true_result = vec_float_dot_product(vec, vec2, DIMENSION);
    cout << "   + Expected result: " << true_result << endl;

    /* Evaluating encrypted dot product and printing result */
    print_line(__LINE__);
    cout << "Evaluating encrypted dot product." << endl;
    Ciphertext product = CKKS_dot_product(evaluator, relin_keys, galois_keys, encrypted_vector, encrypted_vector2, DIMENSION);
    double result = CKKS_result(decryptor, encoder, product);
    cout << "   + Computed result: " << result << endl;

    /* Print the absolute deviation from the true result */
    print_line(__LINE__);
    double deviation = abs(true_result - result);
    cout << "The absolute deviation from the true result is: " << deviation << endl;

    /* Checking that the deviation is within the tolerance */
    print_line(__LINE__);
    cout << "The tolerance is: " << TOLERANCE << endl;
    cout << "The deviation is within the tolerance: " << (deviation < TOLERANCE) << endl << endl;
}