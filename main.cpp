#include <iostream>
#include <string>
#include <vector>
#include "ipv4_analyzer.h"

int main() {
    std::string line;
    size_t lineNumber = 1;

    while (std::getline(std::cin, line)) {
        if (line == "END") {
            break;
        }
        std::vector<std::string> foundIPs;
        if (containsValidIPv4(line, foundIPs)) {
            std::cout << "Line " << lineNumber << ": Valid IPv4 found -> ";
            for (size_t i = 0; i < foundIPs.size(); ++i) {
                std::cout << foundIPs[i] << (i + 1 < foundIPs.size() ? ", " : "");
            }
            std::cout << "\n";
        } else {
            std::cout << "Line " << lineNumber << ": No valid IPv4 found\n";
        }
        lineNumber++;
    }

    return 0;
}
