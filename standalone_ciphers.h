#ifndef STANDALONE_CIPHERS_H
#define STANDALONE_CIPHERS_H

#include <string>
#include <map>
#include <functional>

using DecryptFunc = std::function<bool(
    const std::string& mode,
    const std::string& ct,
    const std::string& key,
    const std::string& iv,
    std::string& plaintext
)>;

void register_standalone_ciphers(std::map<std::string, DecryptFunc>& m);

#endif
