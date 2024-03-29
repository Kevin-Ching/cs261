#include "native/examples/examples.h"
#include "tests.h"

using namespace std;
using namespace seal;

int main()
{
    while (true)
    {
        cout << "+-------------------------------------------------------------+" << endl;
        cout << "| Tests                        | Source Files                 |" << endl;
        cout << "+------------------------------+------------------------------+" << endl;
        cout << "| 1. Integer Dot Product       | 1_integer_dot_product.cpp    |" << endl;
        cout << "| 2. Float Dot Product         | 2_float_dot_product.cpp      |" << endl;
        cout << "| 3. Float Matrix Vector       | 3_float_matrix_vector.cpp    |" << endl;
        cout << "| 4. Packed Matrix Vector      | 4_packed_matrix_vector.cpp   |" << endl;
        cout << "| 5. Timed Packed Products     | 5_timed_packed_products.cpp  |" << endl;
        cout << "+------------------------------+------------------------------+" << endl;

        /*
        Print how much memory we have allocated from the current memory pool.
        By default the memory pool will be a static global pool and the
        MemoryManager class can be used to change it. Most users should have
        little or no reason to touch the memory allocation system.
        */
        size_t megabytes = MemoryManager::GetPool().alloc_byte_count() >> 20;
        cout << "[" << setw(7) << right << megabytes << " MB] "
             << "Total allocation from the memory pool" << endl;

        int selection = 0;
        bool valid = true;
        do
        {
            cout << endl << "> Run test (1 ~ 5) or exit (0): ";
            if (!(cin >> selection))
            {
                valid = false;
            }
            else if (selection < 0 || selection > 5)
            {
                valid = false;
            }
            else
            {
                valid = true;
            }
            if (!valid)
            {
                cout << "  [Beep~~] valid option: type 0 ~ 5" << endl;
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }
        } while (!valid);

        switch (selection)
        {
        case 1:
            test_integer_dot_product();
            break;

        case 2:
            test_float_dot_product();
            break;

        case 3:
            test_float_matrix_vector_product();
            break;

        case 4:
            test_packed_matrix_vector_product();
            break;

        case 5:
            test_timed_packed_products();
            break;

        case 0:
            return 0;
        }
    }

    return 0;
}
