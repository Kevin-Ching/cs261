#include "native/examples/examples.h"
#include "my_utils.h"

using namespace std;
using namespace seal;

unsigned long timed_test_with_num_rows(SEALContext context, size_t NUM_ROWS)
{
    /* Parameters for the test */
    const size_t DIMENSION = 128;
    const double UPPER_BOUND = 1;
    const double LOWER_BOUND = 0;
    const double TOLERANCE = 1e-4;
    const size_t REPS = 10;
    const bool ONE_ROW_MATRIX = false;

    /* Setting scale */
    double scale = pow(2.0, 40);

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

    size_t num_vecs_per_row = slot_count / DIMENSION;
    size_t total_num_vecs = num_vecs_per_row * NUM_ROWS;

    /* Print total number of unpacked vectors */
    print_example_banner("Total number of unpacked vectors: " + to_string(total_num_vecs));

    /* Print number of slots */
    cout << "Number of slots: " << slot_count << endl;

    /* Print dimension of vectors */
    cout << "Dimension of vectors: " << DIMENSION << endl;

    /* Print number of rows */
    cout << "Number of rows: " << NUM_ROWS << endl;

    /* Print the number of vectors per row */
    cout << "Number of vectors per row: " << num_vecs_per_row << endl;

    /* Print tolerance */
    cout << "The tolerance is: " << TOLERANCE << endl;

    /* One row matrix memory "hack" */
    cout << "Using one row matrix memory \"hack\": " << (ONE_ROW_MATRIX ? "true" : "false") << endl;
    size_t old_num_rows = 1;
    if (ONE_ROW_MATRIX)
    {
        old_num_rows = NUM_ROWS;
        NUM_ROWS = 1;
    }    

    /* Setting up PRNG for doubles */
    uniform_real_distribution<double> unif(LOWER_BOUND, UPPER_BOUND);
    random_device rd;
    mt19937 gen(rd());

    /* Run test REP number of times */
    cout << endl << "Running test " << REPS << " times." << endl;

    chrono::high_resolution_clock::time_point time_start, time_end;
    vector<int64_t> times(REPS);
    chrono::milliseconds time_sum(0);
    chrono::milliseconds time_diff;
    

    for (size_t i = 0; i < REPS; i++)
    {
        /* Creating matrix */
        vector<vector<double>> matrix(NUM_ROWS, vector<double>(slot_count, 0ULL));
        for (size_t i = 0; i < NUM_ROWS; i++)
        {
            for (size_t j = 0; j < slot_count; j++)
            {
                matrix[i][j] = unif(gen);
            }
        }

        /* Encoding and encrypting matrix */
        Plaintext plain_vector;
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

        /* Encoding and encrypting vector */
        encoder.encode(duplicated_vec, scale, plain_vector);
        Ciphertext encrypted_vector;
        encryptor.encrypt(plain_vector, encrypted_vector);

        /* Computing true results */
        double first_true_result = vec_float_dot_product(matrix[0], duplicated_vec, DIMENSION);

        /* Timing the encrypted matrix vector product */
        vector<Ciphertext> product_vector;
        time_start = chrono::high_resolution_clock::now();
        for (size_t i = 0; i < old_num_rows; i++)
        {
            product_vector = CKKS_matrix_vector_product(evaluator, relin_keys, galois_keys, encrypted_matrix, encrypted_vector, DIMENSION);
        }
        time_end = chrono::high_resolution_clock::now();
        time_diff = chrono::duration_cast<chrono::milliseconds>(time_end - time_start);

        double first_result = CKKS_result(decryptor, encoder, product_vector[0]);

        /* Checking that the first deviation is within the tolerance */
        if (abs(first_true_result - first_result) >= TOLERANCE)
        {
            cerr << "An absolute deviation was not within the tolerance." << endl;
        }

        /* Record time */
        times[i] = time_diff.count();
        time_sum += time_diff;
    }

    /* Print times */
    cout << "Times in milliseconds: " << endl;
    print_vector(times, times.size());

    /* Print average time */
    auto avg_time = time_sum.count() / REPS;
    cout << "Average time: " << avg_time << " milliseconds" << endl;
    return avg_time;
}

void test_timed_packed_products()
{
    print_example_banner("Test: Timed Packed Matrix Vector Product");

    /* Setting parameters */
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    /* Creating context */
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // timed_test_with_num_rows(context, 8);   // 256 vectors
    // timed_test_with_num_rows(context, 16;  // 512 vectors
    // timed_test_with_num_rows(context, 32);  // 1024 vectors
    // timed_test_with_num_rows(context, 64);  // 2048 vectors
    // timed_test_with_num_rows(context, 3125);  // 100k vectors

    /* Change these input parameters */
    size_t start = 8;
    size_t end = 32;

    vector<unsigned long> avg_times;
    for (size_t num_rows = start; num_rows <= end; num_rows *= 2)
    {
        avg_times.push_back(timed_test_with_num_rows(context, num_rows));
    }

    cout << endl << "All average times: " << endl;
    print_vector(avg_times, avg_times.size());

    cout << endl;
}