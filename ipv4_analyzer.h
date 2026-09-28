#ifndef IPV4_ANALYZER_H
#define IPV4_ANALYZER_H

#include <string>
#include <vector>

// Helper to check if a token is a valid IPv4 octet (0-255, no leading zeros unless single '0')
bool isValidOctet(const std::string& octet);

// Determines if there is a valid IPv4 contained within the line and extracts all valid occurrences
bool containsValidIPv4(const std::string& line, std::vector<std::string>& matches);

#endif // IPV4_ANALYZER_H
