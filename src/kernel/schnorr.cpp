/*  CryptoKernel - A library for creating blockchain based digital currency
    Copyright (C) 2016  James Lovejoy

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <sstream>
#include <algorithm>
#include <iomanip>
#include <cstring>

#include <cschnorr/signature.h>

#include "schnorr.h"
#include "base64.h"

CryptoKernel::Schnorr::Schnorr() {
    schnorr_context* ctx = schnorr_context_new();
    musig_key* musign_key = musig_key_new(ctx);

    if(musig_key == NULL) {
        throw std::runtime_error("Could not generate key pair");
    }
}

CryptoKernel::Schnorr::~Schnorr() {
    schnorr_context_free(ctx);
    // TODO: musig_free(musign_key);
}

bool CryptoKernel::Schnorr::verify(const std::string& message,
                                  const std::string& signature) {

    // const std::string messageHash = sha256(message);
    // const std::string decodedSignature = base64_decode(signature);

    // BN_hex2point
    // BN_bn2hex
    // EC_POINT_hex2point
    // EC_POINT_point2hex

    // Point is 33 bytes with 1 bit z ; s should be 32 bytes
    // need to serialize this -> buffer convert to base64
    // need to hex functions and buffer functions
    // buffer would be more precise -> creates unsigned char 

    // BN_bn2bin
    // BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
    // get converts from type to str 
    // set converts from str to type

    // EC_POINT_point2buf

    char* sHex = BN_bn2hex(signature->s);
    char* AHex = EC_POINT_point2hex(ctx->group, pub->A, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx);
    char* RHex = EC_POINT_point2hex(ctx->group, sigAgg->R, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx);

    std::string newString(sHex);

    OPENSSL_free(sHex);

    if(!schnorr_verify(
        ctx,
        const schnorr_sig* sig,
        musig_key.pub,
        reinterpret_cast<unsigned char*>(const_cast<char*>(message)),
        message.length())
    ) {
        return false;
    }

    if(!ECDSA_verify(0, (unsigned char*)messageHash.c_str(), (int)messageHash.size(),
                     (unsigned char*)decodedSignature.c_str(), (int)decodedSignature.size(), eckey)) {
        return false;
    }

    return true;
}

std::string CryptoKernel::Schnorr::sign(const std::string& message) {
    if(musig_key != NULL) {

        schnorr_sig** buffer;

        if(!schnorr_sign(ctx,
                         buffer,  // figure out
                         musig_key, 
                         reinterpret_cast<unsigned char*>(message.c_str()),
                         message.size()) {
            delete[] buffer;
            throw std::runtime_error("Could not sign message");
        } else {
            const std::string returning = base64_encode(buffer, buffer.length());
            delete[] buffer;
            return returning;
        }
    } else {
        return "";
    }
}

std::string CryptoKernel::Schnorr::getPublicKey() {
    if(musig_key != NULL) {
        unsigned char *buf;

        if (EC_POINT_point2buf(ctx->group, musig_key->pub->A,
                           POINT_CONVERSION_COMPRESSED,
                           &buf, ctx->bn_ctx) != 33) {
            return "";
        }

        const std::string returning = base64_encode(buf, 33);

        OPENSSL_free(buf);

        return returning;
    } else {
        return "";
    }
}

std::string CryptoKernel::Schnorr::getPrivateKey() {
    if(musig_key != NULL) {
        unsigned char *buf = malloc(sizeof(unsigned char) * 32);

        if (BN_bn2binpad(musig_key->a, &buf, 32) != 32) {
            return ""
        }

        const std::string returning = base64_encode(buf, 32);

        free(buf);

        return returning;
    } else {
        return "";
    }
}

bool CryptoKernel::Schnorr::setPublicKey(const std::string& publicKey) {
    const std::string decodedKey = base64_decode(publicKey);

    if(!EC_KEY_oct2key(eckey, (unsigned char*)decodedKey.c_str(),
                       (unsigned int)decodedKey.size(), NULL)) {
        return false;
    } else {
        return true;
    }
}

bool CryptoKernel::Schnorr::setPrivateKey(const std::string& privateKey) {
    const std::string decodedKey = base64_decode(privateKey);

    BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);

    if(!EC_KEY_oct2priv(eckey, (unsigned char*)decodedKey.c_str(),
                        (unsigned int)decodedKey.size())) {
        throw std::runtime_error("Could not copy private key");
    } else {
        BN_CTX* ctx = BN_CTX_new();

        EC_POINT* pub_key = EC_POINT_new(ecgroup);
        if(!EC_POINT_mul(ecgroup, pub_key,
                     EC_KEY_get0_private_key(eckey), nullptr,
                     nullptr, ctx)) {
            BN_CTX_free(ctx);
            return false;
        }

        BN_CTX_free(ctx);

        if(!EC_KEY_set_public_key(eckey, pub_key)) {
            EC_POINT_free(pub_key);
            return false;
        }

        return musig_key != NULL;
    }
}

bool CryptoKernel::Schnorr::getStatus() {
    return true;
}