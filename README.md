# 581 Assignment 1
## Building
Using cmake, run the following command:
```shell
cmake -B build && cmake --build build 
```
Then run the program with
```./build/581_A1 < input_file.txt```
where input_file.txt is your input file.
### Testing
*After building*
```shell
ctest --test-dir build
```