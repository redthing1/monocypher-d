import core.stdc.stdio;
import core.stdc.string;
import core.stdc.stdlib;

import std.algorithm : map;
import std.conv : to;
import std.array : array;

// import monocypher;

int main(string[] args) {
    int argc = cast(int) args.length;
    char** argv = args.map!(a => a.to!(char[]).ptr).array.ptr;

    if (argc != 3) {
        printf("Usage: %s <input> <key>\n", argv[0]);
        return 1;
    }
    // read input string from arg 0
    char* input = argv[1];

    enum size_t INPUT_MAX = 1024;
    if (strlen(input) > INPUT_MAX) {
        printf("input string too long!\n");
        return 1;
    }

    return 0;
}
