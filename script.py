import subprocess

def run_cpp_interactively(executable_path):
    try:
        # Start the C++ executable process
        process = subprocess.Popen([executable_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Provide input to the process
        input_data_1 = "5\n"
        process.stdin.write(input_data_1)
        process.stdin.flush()

        # Read and print output until a specific marker is encountered
        while True:
            line = process.stdout.readline()
            print(line, end='')
            if line.strip() == "> Run test (1 ~ 5) or exit (0):":
                break

        # Provide additional input
        input_data_2 = "0\n"
        process.stdin.write(input_data_2)
        process.stdin.flush()

        # Read and print output until another marker is encountered
        while True:
            line = process.stdout.readline()
            print(line, end='')
            if line.strip() == "> Run test (1 ~ 5) or exit (0):":
                break

        # Check if the process ran successfully
        process.wait()
        if process.returncode == 0:
            print("C++ executable ran successfully.")
        else:
            print("Error running C++ executable. Exit code:", process.returncode)
    except Exception as e:
        print("Exception:", e)

cpp_executable_path = './build/tests'
run_cpp_interactively(cpp_executable_path)
