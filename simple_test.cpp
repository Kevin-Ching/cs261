#include "native/examples/examples.h"
#include "my_utils.h"

using namespace std;
using namespace seal;

int main()
{
    print_example_banner("Test: Simple Length 4 Dot Product");

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

    /* Creating matrix 1 */
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;

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
    pod_matrix2[0] = 4ULL;
    pod_matrix2[1] = 5ULL;
    pod_matrix2[2] = 6ULL;
    pod_matrix2[3] = 7ULL;

    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << endl;
    cout << "Second input plaintext matrix:" << endl;
    print_matrix(pod_matrix2, row_size);

    /* Add the two matrices */
    print_line(__LINE__);
    cout << "Summing the matrices." << endl;
    evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
    cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    /* Decrypt and decode the result */
    print_line(__LINE__);
    Plaintext plain_result;
    cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    vector<uint64_t> pod_result;
    batch_encoder.decode(plain_result, pod_result);
    cout << "    + Result plaintext matrix ...... Correct." << endl;
    print_matrix(pod_result, row_size);
}