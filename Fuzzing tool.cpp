#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <cstdlib>
#include <chrono>
#include <csignal>

int total_tests = 0;
int crashes = 0;
std::vector<std::string> seed_corpus;

void signal_handler(int signal) {
    std::cerr << "\nCrash detected! Signal: " << signal << std::endl;
    crashes++;
}

std::string generate_random_data(size_t max_length) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<int> dist(0, 255);

    std::uniform_int_distribution<size_t> len_dist(1, max_length);
    size_t length = len_dist(gen);
    std::string data;
    data.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        data.push_back(static_cast<char>(dist(gen)));
    }

    return data;
}

std::string mutate_input(const std::string& input) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 3);

    std::string mutated = input;
    int mutation_type = dist(gen);

    switch (mutation_type) {
    case 0: {
        std::uniform_int_distribution<size_t> pos_dist(0, mutated.size());
        size_t pos = pos_dist(gen);
        std::uniform_int_distribution<size_t> n_dist(1, 10);
        size_t n = n_dist(gen);
        std::string extra;
        for (size_t i = 0; i < n; ++i) {
            extra.push_back(static_cast<char>(dist(gen)));
        }
        mutated.insert(pos, extra);
        break;
    }
    case 1:
        if (!mutated.empty()) {
            std::uniform_int_distribution<size_t> pos_dist(0, mutated.size() - 1);
            size_t pos = pos_dist(gen);
            size_t max_len = std::min(mutated.size() - pos, static_cast<size_t>(10));
            std::uniform_int_distribution<size_t> len_dist(1, max_len);
            size_t len = len_dist(gen);
            mutated.erase(pos, len);
        }
        break;
    case 2:
        if (!mutated.empty()) {
            size_t max_n = std::min(mutated.size(), static_cast<size_t>(10));
            std::uniform_int_distribution<size_t> n_dist(1, max_n);
            size_t n = n_dist(gen);
            for (size_t i = 0; i < n; ++i) {
                std::uniform_int_distribution<size_t> pos_dist(0, mutated.size() - 1);
                size_t pos = pos_dist(gen);
                mutated[pos] = static_cast<char>(dist(gen));
            }
        }
        break;
    case 3:
        if (mutated.size() > 1) {
            std::uniform_int_distribution<size_t> pos1_dist(0, mutated.size() / 2);
            size_t pos1 = pos1_dist(gen);
            std::uniform_int_distribution<size_t> pos2_dist(mutated.size() / 2, mutated.size() - 1);
            size_t pos2 = pos2_dist(gen);
            std::swap_ranges(mutated.begin() + pos1, mutated.begin() + pos1 + 1, mutated.begin() + pos2);
        }
        break;
    }

    return mutated;
}

void run_target(const std::string& target_program, const std::string& test_case) {
    std::ofstream temp_file("temp_fuzz_input");
    temp_file << test_case;
    temp_file.close();

    std::string command = target_program + " temp_fuzz_input";

    signal(SIGSEGV, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGILL, signal_handler);
    signal(SIGFPE, signal_handler);

    int result = system(command.c_str());

    remove("temp_fuzz_input");

    if (result != 0) {
        std::ofstream crash_file("crash_" + std::to_string(crashes) + ".input");
        crash_file << test_case;
        crash_file.close();
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target_program> [seed_dir] [iterations]" << std::endl;
        return 1;
    }

    std::string target_program = argv[1];
    std::string seed_dir = (argc > 2) ? argv[2] : "";
    int iterations = (argc > 3) ? std::stoi(argv[3]) : 1000;

    if (!seed_dir.empty()) {
        seed_corpus = {
            "normal input",
            "very very very long input.........................................................................",
            "",
            "\x00\x01\x02\x03\x04",
            "!@#$%^&*()"
        };
    }

    auto start_time = std::chrono::steady_clock::now();

    std::random_device rd;
    std::mt19937 gen(rd());
    std::bernoulli_distribution bernoulli_dist(0.7);
    std::uniform_int_distribution<size_t> corpus_dist(0, seed_corpus.empty() ? 0 : seed_corpus.size() - 1);

    for (int i = 0; i < iterations; ++i) {
        std::string test_case;

        if (!seed_corpus.empty() && bernoulli_dist(gen)) {
            const std::string& seed = seed_corpus[corpus_dist(gen)];
            test_case = mutate_input(seed);
        }
        else {
            test_case = generate_random_data(1024);
        }

        run_target(target_program, test_case);
        total_tests++;

        if (i % 100 == 0) {
            std::cout << "Progress: " << i << "/" << iterations
                << " tests, " << crashes << " crashes found\r" << std::flush;
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

    std::cout << "\n\nFuzzing completed!" << std::endl;
    std::cout << "Total tests: " << total_tests << std::endl;
    std::cout << "Crashes found: " << crashes << std::endl;
    std::cout << "Time elapsed: " << duration.count() << " seconds" << std::endl;

    return 0;
}
