#include <boost/python.hpp>

#include "crypto/crypto.h"

using namespace boost::python;

void checkPublicKeySize (const std::string& publicKey) {
    if (publicKey.size() != sizeof(crypto::public_key)) {
        throw std::runtime_error("Wrong public key size");
    }
}

void checkSecretKeySize (const std::string& secretKey) {
    if (secretKey.size() != sizeof(crypto::secret_key)) {
        throw std::runtime_error("Wrong secret key size");
    }
}

void checkSignatureSize(const std::string& signature) {
    if (signature.size() != sizeof(crypto::signature)) {
        throw std::runtime_error("Wrong signature size");
    }
}

std::string sign(const std::string& message, const std::string& secretKeyStr, const std::string& publicKeyStr) {
    checkPublicKeySize(publicKeyStr);
    checkSecretKeySize(secretKeyStr);

    const auto pub = *reinterpret_cast<const crypto::public_key*>(publicKeyStr.c_str());
    const auto secret = *reinterpret_cast<const crypto::secret_key*>(secretKeyStr.c_str());
    auto hash = crypto::cn_fast_hash(message.c_str(), message.size());

    crypto::signature signature;
    crypto::generate_signature(hash, pub, secret, signature);

    return std::string(reinterpret_cast<char*>(&signature), sizeof(signature));
}

bool check_signature(const std::string& message, const std::string& publicKeyStr, const std::string& signatureStr) {
    checkSignatureSize(signatureStr);
    checkPublicKeySize(publicKeyStr);

    const auto pub = *reinterpret_cast<const crypto::public_key*>(publicKeyStr.c_str());
    const auto signature = *reinterpret_cast<const crypto::signature*>(signatureStr.c_str());
    auto hash = crypto::cn_fast_hash(message.c_str(), message.size());

    return crypto::check_signature(hash, pub, signature);
}

BOOST_PYTHON_MODULE(cryptonote) {
    def("check_signature", check_signature);
    def("sign", sign);
}
