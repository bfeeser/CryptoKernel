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
#include <cstdio>

#include "schnorr.h"
#include "base64.h"

CryptoKernel::Schnorr::Schnorr() {
    ctx = schnorr_context_new();
    key = musig_key_new(ctx);

    if (key == NULL) {
        throw std::runtime_error("Could not generate key pair");
    }
}

CryptoKernel::Schnorr::~Schnorr() {
    schnorr_context_free(ctx);
    // TODO(metalicjames): musig_key_free(key);
}

bool CryptoKernel::Schnorr::verify(const std::string& message,
                                   const std::string& signature) {
    const std::string decodedSignature = base64_decode(signature);

    musig_sig* sig = NULL;
    sig = reinterpret_cast<musig_sig*>(malloc(sizeof(musig_sig)));
    if (sig == NULL) {
        return false;
    }
    sig->s = NULL;
    sig->R = NULL;

    sig->s = BN_new();
    if (sig->s == NULL) {
        return false;
    }

    sig->R = EC_POINT_new(ctx->group);
    if (sig->R == NULL) {
        return false;
    }

    if (!BN_bin2bn((unsigned char*)decodedSignature.c_str(), 32, sig->s)) {
        return false;
    }

    if (!EC_POINT_oct2point(
        ctx->group,
        sig->R,
        (unsigned char*)decodedSignature.c_str() + 32,
        33,
        ctx->bn_ctx)) {
        return false;
    }

    if (xmusig_verify(
        ctx,
        sig,
        key->pub,
        (unsigned char*)message.c_str(),
        message.size()) != 1) {

        printf("\nverify sig->s: %s\n", BN_bn2hex(sig->s));
        printf("verify sig->R: %s\n", EC_POINT_point2hex(ctx->group, sig->R, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
        printf("verify pub->A: %s\n", EC_POINT_point2hex(ctx->group, key->pub->A, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
        printf("verify pub->R: %s\n", EC_POINT_point2hex(ctx->group, key->pub->R, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));

        return false;
    }

    return true;
}

std::string CryptoKernel::Schnorr::sign(const std::string& message) {
    if (key != NULL) {
        musig_sig* sig;
        musig_pubkey* pub;
        musig_pubkey* pubkeys[1];
        pubkeys[0] = key->pub;

        if (musig_sign(
            ctx,
            &sig,
            &pub,
            key,
            pubkeys,
            1,
            (unsigned char*)message.c_str(),
            message.size()) == 0) {
            delete[] sig;

            throw std::runtime_error("Could not sign message");
        } else {
            if (xmusig_verify(
                    ctx,
                    sig,
                    key->pub,
                    (unsigned char*)message.c_str(),
                    message.size()) != 1) {

                printf("\nsign sig->s: %s\n", BN_bn2hex(sig->s));
                printf("sign sig->R: %s\n", EC_POINT_point2hex(ctx->group, sig->R, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
                printf("sign pub->A: %s\n", EC_POINT_point2hex(ctx->group, key->pub->A, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
                printf("sign pub->R: %s\n", EC_POINT_point2hex(ctx->group, key->pub->R, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
            }

            unsigned int buf_len = 65;
            unsigned char *buf;
            buf = new unsigned char[buf_len];

            if (BN_bn2binpad(sig->s, buf, 32) != 32) {
                throw std::runtime_error("Failed to encode s");
            }

            if (EC_POINT_point2oct(
                    ctx->group,
                    sig->R,
                    POINT_CONVERSION_COMPRESSED,
                    buf + 32,
                    33,
                    ctx->bn_ctx) != 33) {
                throw std::runtime_error("Failed to encode R");
            }

            const std::string returning = base64_encode(buf, 65);

            delete[] sig;
            delete[] buf;

            return returning;
        }
    } else {
        return "";
    }
}


int CryptoKernel::Schnorr::xmusig_verify(const schnorr_context* ctx,
                 const musig_sig* sig,
                 const musig_pubkey* pubkey,
                 const unsigned char* msg,
                 const size_t len) {
    EC_POINT* sG = NULL;
    EC_POINT* HX = NULL;
    BIGNUM* tmp = NULL;
    int error = 0;

    sG = EC_POINT_new(ctx->group);
    if (sG == NULL) {
        return -1;
    }

    if (EC_POINT_mul(ctx->group, sG, NULL, ctx->G, sig->s, ctx->bn_ctx) == 0) {
        return -1;
    }

    unsigned char h1_buf[33 + 33 + 32];
    if (hash((unsigned char*)&h1_buf + 66, msg, len) == 0) {
        return -1;
    }
    
    if (EC_POINT_point2oct(ctx->group,
                          pubkey->A,
                          POINT_CONVERSION_COMPRESSED,
                          (unsigned char*)&h1_buf,
                          33,
                          ctx->bn_ctx) != 33) {
        return -1;
    }

    if (EC_POINT_point2oct(ctx->group, 
                          sig->R, 
                          POINT_CONVERSION_COMPRESSED, 
                          (unsigned char*)&h1_buf + 33, 
                          33,
                          ctx->bn_ctx) != 33) {
        return -1;
    }

    unsigned char h1[32];
    if (hash((unsigned char*)&h1, (unsigned char*)&h1_buf, 33+33+32) == 0) {
        return -1;
    }

    tmp = BN_new();
    if (tmp == NULL) {
        return -1;
    }

    if (BN_bin2bn((unsigned char*)&h1, 32, tmp) == NULL) {
        return -1;
    }

    HX = EC_POINT_new(ctx->group);
    if (HX == NULL) {
        return -1;
    }

    if (EC_POINT_mul(ctx->group, HX, NULL, pubkey->A, tmp, ctx->bn_ctx) == 0) {
        return -1;
    }

    if (EC_POINT_add(ctx->group, HX, HX, sig->R, ctx->bn_ctx) == 0) {
        return -1;
    }

    printf("\nxmusig_verify pubkey->A: %s\n", EC_POINT_point2hex(ctx->group, pubkey->A, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
    printf("xmusig_verify pubkey->R: %s\n", EC_POINT_point2hex(ctx->group, pubkey->R, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
    printf("xmusig_verify sig->s: %s\n", BN_bn2hex(sig->s));
    printf("xmusig_verify sig->R: %s\n", EC_POINT_point2hex(ctx->group, sig->R, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
    printf("xmusig_verify sG: %s\n", EC_POINT_point2hex(ctx->group, sG, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
    printf("xmusig_verify HX: %s\n", EC_POINT_point2hex(ctx->group, HX, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));

    const int res = EC_POINT_cmp(ctx->group, HX, sG, ctx->bn_ctx);
    switch(res) {
        case 0:
            break;
        case 1:
            return -1;
        default:
            return -1;
    }

    error = 1;

    EC_POINT_free(sG);
    EC_POINT_free(HX);
    BN_free(tmp);

    return error;
}


std::string CryptoKernel::Schnorr::getPublicKey() {
    if (key != NULL) {
        unsigned int buf_len = 33;
        unsigned char *buf;
        buf = new unsigned char[buf_len];

        printf("\nget pub->A: %s\n", EC_POINT_point2hex(ctx->group, key->pub->A, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
        printf("get pub->R: %s\n", EC_POINT_point2hex(ctx->group, key->pub->R, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));

        if (EC_POINT_point2oct(
                ctx->group,
                key->pub->A,
                POINT_CONVERSION_COMPRESSED,
                buf,
                buf_len,
                ctx->bn_ctx) != buf_len) {
            return "";
        }

        const std::string returning = base64_encode(buf, buf_len);

        delete[] buf;

        return returning;
    } else {
        return "";
    }
}

std::string CryptoKernel::Schnorr::getPrivateKey() {
    if (key != NULL) {
        int buf_len = 32;
        unsigned char *buf;
        buf = new unsigned char[buf_len];

        if (BN_bn2binpad(key->a, buf, buf_len) != buf_len) {
            return "";
        }

        const std::string returning = base64_encode(buf, buf_len);

        delete[] buf;

        return returning;
    } else {
        return "";
    }
}

bool CryptoKernel::Schnorr::setPublicKey(const std::string& publicKey) {
    const std::string decodedKey = base64_decode(publicKey);



    if (!EC_POINT_oct2point(
            ctx->group,
            key->pub->A,
            (unsigned char*)decodedKey.c_str(),
            decodedKey.size(),
            ctx->bn_ctx)) {
        return false;
    }

    printf("\nset pub->A: %s\n", EC_POINT_point2hex(ctx->group, key->pub->A, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
    printf("set pub->R: %s\n", EC_POINT_point2hex(ctx->group, key->pub->R, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));

    return true;
}

bool CryptoKernel::Schnorr::setPrivateKey(const std::string& privateKey) {
    const std::string decodedKey = base64_decode(privateKey);

    if (!BN_bin2bn(
            (unsigned char*)decodedKey.c_str(),
            (unsigned int)decodedKey.size(),
            key->a)) {
        return false;
    }
    return true;
}


bool CryptoKernel::Schnorr::getStatus() {
    return true;
}
