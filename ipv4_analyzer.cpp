#include "ipv4_analyzer.h"
#include <cctype>

bool isValidOctet(const std::string& octet) {
    if (octet.empty() || octet.size() > 3) {
        return false;
    }
    for (char c : octet) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    if (octet.size() > 1 && octet[0] == '0') {
        return false;
    }
    int value = std::stoi(octet);
    return value >= 0 && value <= 255;
}

bool containsValidIPv4(const std::string& line, std::vector<std::string>& matches) {
    size_t n = line.size();
    size_t i = 0;

    while (i < n) {
        // Boundary check before start: cannot be preceded by an alphanumeric char
        if (i > 0 && std::isalnum(static_cast<unsigned char>(line[i - 1]))) {
            i++;
            continue;
        }

        // If preceded by a dot, cannot have an alphanumeric or another dot before that dot
        if (i > 0 && line[i - 1] == '.') {
            if (i > 1 && (std::isalnum(static_cast<unsigned char>(line[i - 2])) || line[i - 2] == '.')) {
                i++;
                continue;
            }
        }

        if (!std::isdigit(static_cast<unsigned char>(line[i]))) {
            i++;
            continue;
        }

        // Try to parse 4 octets separated by 3 dots starting at index i
        size_t curr = i;
        bool valid = true;
        std::vector<std::string> octets;

        for (int part = 0; part < 4; ++part) {
            if (part > 0) {
                if (curr < n && line[curr] == '.') {
                    curr++; // consume dot
                } else {
                    valid = false;
                    break;
                }
            }

            size_t startOctet = curr;
            while (curr < n && std::isdigit(static_cast<unsigned char>(line[curr]))) {
                curr++;
            }

            std::string octet = line.substr(startOctet, curr - startOctet);
            if (!isValidOctet(octet)) {
                valid = false;
                break;
            }
            octets.push_back(octet);
        }

        if (valid && octets.size() == 4) {
            // Boundary check after end:
            // 1. Cannot be followed by an alphanumeric character
            // 2. If followed by a dot, that dot must NOT be followed by an alnum char or another dot
            bool boundaryValid = true;
            if (curr < n) {
                if (std::isalnum(static_cast<unsigned char>(line[curr]))) {
                    boundaryValid = false;
                } else if (line[curr] == '.') {
                    if (curr + 1 < n && (std::isalnum(static_cast<unsigned char>(line[curr + 1])) || line[curr + 1] == '.')) {
                        boundaryValid = false;
                    }
                }
            }

            if (boundaryValid) {
                std::string ip = line.substr(i, curr - i);
                matches.push_back(ip);
                i = curr;
                continue;
            }
        }

        i++;
    }

    return !matches.empty();
}
