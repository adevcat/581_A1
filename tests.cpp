#include "ipv4_analyzer.h"
#include <iostream>
#include <cassert>
#include <vector>
#include <string>

int g_tests_run = 0;
int g_tests_passed = 0;

void runTest(const std::string& testName, bool condition) {
    g_tests_run++;
    if (condition) {
        g_tests_passed++;
        std::cout << "  [PASS] " << testName << "\n";
    } else {
        std::cerr << "  [FAIL] " << testName << "\n";
    }
}

void testOctetValidation() {
    std::cout << "=== Octet Validation Unit Tests ===\n";
    runTest("Valid single digit '0'", isValidOctet("0") == true);
    runTest("Valid single digit '5'", isValidOctet("5") == true);
    runTest("Valid double digit '42'", isValidOctet("42") == true);
    runTest("Valid upper boundary '255'", isValidOctet("255") == true);
    runTest("Valid standard '192'", isValidOctet("192") == true);
    runTest("Valid standard '10'", isValidOctet("10") == true);

    runTest("Invalid empty string", isValidOctet("") == false);
    runTest("Invalid upper out-of-range '256'", isValidOctet("256") == false);
    runTest("Invalid upper out-of-range '999'", isValidOctet("999") == false);
    runTest("Invalid leading zero '01'", isValidOctet("01") == false);
    runTest("Invalid leading zero '00'", isValidOctet("00") == false);
    runTest("Invalid leading zero '000'", isValidOctet("000") == false);
    runTest("Invalid leading zero '050'", isValidOctet("050") == false);
    runTest("Invalid negative sign '-1'", isValidOctet("-1") == false);
    runTest("Invalid non-digit chars '1a'", isValidOctet("1a") == false);
    runTest("Invalid length > 3 digits '1000'", isValidOctet("1000") == false);
    runTest("Invalid whitespace prefix ' 1'", isValidOctet(" 1") == false);
    runTest("Invalid special symbols '$5'", isValidOctet("$5") == false);
}

void testSingleIPv4Detection() {
    std::cout << "\n=== Single IPv4 Detection Tests ===\n";
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("192.168.1.1", matches);
        runTest("Exact single valid IP", found && matches == std::vector<std::string>{"192.168.1.1"});
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("0.0.0.0", matches);
        runTest("Minimum boundary IP (0.0.0.0)", found && matches == std::vector<std::string>{"0.0.0.0"});
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("255.255.255.255", matches);
        runTest("Maximum boundary IP (255.255.255.255)", found && matches == std::vector<std::string>{"255.255.255.255"});
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("Loopback address 127.0.0.1 in sentence", matches);
        runTest("Loopback address within sentence", found && matches == std::vector<std::string>{"127.0.0.1"});
    }
}

void testMultipleIPv4Detection() {
    std::cout << "\n=== Multiple IPv4 Extraction Tests ===\n";
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("192.168.1.1 10.0.0.1", matches);
        runTest("Space-separated IPs", found && matches == std::vector<std::string>{"192.168.1.1", "10.0.0.1"});
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("1.1.1.1,2.2.2.2;3.3.3.3", matches);
        runTest("Comma and semicolon separated IPs", found && matches == std::vector<std::string>{"1.1.1.1", "2.2.2.2", "3.3.3.3"});
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("[192.168.0.100] (10.20.30.40) \"172.31.0.1\" <8.8.8.8>", matches);
        runTest("IPs enclosed in brackets, parentheses, quotes, angles",
                found && matches == std::vector<std::string>{"192.168.0.100", "10.20.30.40", "172.31.0.1", "8.8.8.8"});
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("Connect 10.0.0.1:8080 or fallback to 172.16.254.1.", matches);
        runTest("IPs with port suffix and sentence-ending period",
                found && matches == std::vector<std::string>{"10.0.0.1", "172.16.254.1"});
    }
}

void testNegativeCases() {
    std::cout << "\n=== Malformed & Negative Cases ===\n";
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("Invalid octet 256.1.1.1 or 1.256.1.1 or 1.1.256.1 or 1.1.1.256", matches);
        runTest("Reject octets > 255", !found && matches.empty());
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("Leading zeros: 01.1.1.1, 1.01.1.1, 1.1.001.1, 1.1.1.00", matches);
        runTest("Reject leading zeros in any octet", !found && matches.empty());
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("Version numbers like 1.2.3.4.5 and 1.2.3.4.5.6", matches);
        runTest("Reject sequences with 5 or more octets", !found && matches.empty());
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("Short sequences like 1.2.3 and 192.168", matches);
        runTest("Reject incomplete 2 or 3 octet sequences", !found && matches.empty());
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("Consecutive dots 192..168.1.1 and 192.168.1..1", matches);
        runTest("Reject consecutive dots / empty octets", !found && matches.empty());
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("Letters inside octet: 192.168.1a.1 and 192.168.x.1", matches);
        runTest("Reject letters inside octets", !found && matches.empty());
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("Embedded words: abc192.168.1.1, 192.168.1.1xyz, test192.168.1.1end", matches);
        runTest("Reject alphanumeric word prefixes/suffixes", !found && matches.empty());
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("", matches);
        runTest("Empty string input", !found && matches.empty());
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("   \t  \n  ", matches);
        runTest("Whitespace-only input", !found && matches.empty());
    }
}

void testMixedScenarios() {
    std::cout << "\n=== Mixed Valid and Invalid Scenarios ===\n";
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("invalid 256.1.1.1 followed by valid 192.168.1.1 and 5-octet 1.2.3.4.5", matches);
        runTest("Extract only valid IP amidst invalid patterns",
                found && matches == std::vector<std::string>{"192.168.1.1"});
    }
    {
        std::vector<std::string> matches;
        bool found = containsValidIPv4("Prefix dot .192.168.1.1 and suffix dot 10.0.0.1.", matches);
        runTest("Handle isolated leading/trailing dot punctuation correctly",
                found && matches == std::vector<std::string>{"192.168.1.1", "10.0.0.1"});
    }
}

int main() {
    testOctetValidation();
    testSingleIPv4Detection();
    testMultipleIPv4Detection();
    testNegativeCases();
    testMixedScenarios();

    std::cout << "\n=====================================\n";
    std::cout << "Test Suite Summary: " << g_tests_passed << "/" << g_tests_run << " tests passed.\n";
    std::cout << "=====================================\n";

    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
