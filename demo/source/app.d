import std.stdio;
import std.string;
import std.algorithm : map;
import std.conv : to;
import std.array : array, appender;
import core.stdc.string;
import core.stdc.stdlib;

import monocypher;

void mooncypher_argon2_hash_password(ubyte[] pass, ubyte[] salt, ubyte[] key, int blocks_factor = 200, int passes = 4) {
    crypto_argon2_config a2_cfg;
    crypto_argon2_inputs a2_in;
    crypto_argon2_extras a2_ex;

    // a2 config
    a2_cfg.algorithm = CRYPTO_ARGON2_ID;
    a2_cfg.nb_blocks = blocks_factor * 1024; // blocks factor is memory hardness: ~100 is recommended
    a2_cfg.nb_passes = passes; // passes is compute hardness: >= 3 is recommended
    a2_cfg.nb_lanes = 1;

    // a2 inputs
    a2_in.pass = cast(ubyte*) pass;
    a2_in.pass_size = cast(int) pass.length;
    a2_in.salt = cast(ubyte*) salt;
    a2_in.salt_size = cast(int) salt.length;

    // run a2
    // void* a2_work = malloc(a2_cfg.nb_blocks * 1024);
    auto a2_work_buf_size = a2_cfg.nb_blocks * 1024;
    ubyte[] a2_work = new ubyte[a2_work_buf_size];
    crypto_argon2(cast(ubyte*) key, cast(int) key.length, cast(void*) a2_work, a2_cfg, a2_in, a2_ex);
    // free(a2_work);
}

void mooncypher_securerandom(ubyte[] buf) {
    sol_randombytes(cast(void*) buf, buf.length);
}

string hexdump(ubyte[] buf) {
    auto sb = appender!string;
    foreach (i, b; buf) {
        sb ~= format("%02x", b);
    }
    return sb.data;
}

int main(string[] args) {
    if (args.length != 3) {
        writefln("Usage: %s <input> <key>\n", args[0]);
        return 1;
    }

    // read input string
    string input_str = args[1];
    ubyte[] input_bytes = cast(ubyte[]) input_str;
    // read key
    string key_str = args[2];
    ubyte[] key_bytes = cast(ubyte[]) key_str;

    // hash the key
    writefln("hash(%s)", key_str);
    ubyte[32] salt;
    mooncypher_securerandom(salt);
    writefln("  salt: %s", hexdump(salt));
    ubyte[32] crypt_key;
    // reduced complexity argon2 for speed
    mooncypher_argon2_hash_password(key_bytes, salt, crypt_key, 10, 2);
    writefln("  key: %s", hexdump(crypt_key));

    // encrypt the input
    writefln("crypt1(%s)", input_str);
    writefln("  plain: %s", hexdump(input_bytes));
    ubyte[24] crypt1_nonce;
    mooncypher_securerandom(crypt1_nonce);
    writefln("  nonce: %s", hexdump(crypt1_nonce));
    ubyte[16] crypt1_mac;
    ubyte[] crypt1_crypt = new ubyte[input_bytes.length];
    crypto_aead_lock(cast(ubyte*) crypt1_crypt, cast(ubyte*) crypt1_mac, cast(ubyte*) crypt_key, cast(
            ubyte*) crypt1_nonce, null, 0, cast(ubyte*) input_bytes, cast(int) input_bytes.length);
    writefln("  crypt: %s", hexdump(crypt1_crypt));
    writefln("  mac: %s", hexdump(crypt1_mac));

    // decrypt the input
    writefln("decrypt1(%s)", hexdump(crypt1_crypt));
    ubyte[] decrypt1_plain = new ubyte[crypt1_crypt.length];

    int decrypt1_result = crypto_aead_unlock(cast(ubyte*) decrypt1_plain, cast(ubyte*) crypt1_mac, cast(ubyte*) crypt_key, cast(
            ubyte*) crypt1_nonce, null, 0, cast(ubyte*) crypt1_crypt, cast(int) crypt1_crypt.length);
    writefln("  plain: %s", hexdump(decrypt1_plain));
    writefln("  valid: %s", decrypt1_result == 0 ? "true" : "false");

    return 0;
}
