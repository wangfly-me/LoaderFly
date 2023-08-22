#pragma once
#include<string>
#include<assert.h>
#include<iostream>

namespace ko{
    class Base64{
        private:
        static const std::string baseString;
        public:
        static std::string encode(const std::string& s);
        static std::string decode(const std::string& s);
    };
}

const std::string ko::Base64::baseString =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::string ko::Base64::encode(const std::string& s) {
    unsigned char array3[3];
    unsigned char array4[4];
    unsigned group = s.length() / 3;
    unsigned remain = s.length() - 3 * group;
    int pos = 0;
    std::string ret;
    ret.reserve(4 * group + 4);
    for (int g = 0; g < group; ++g) {
        for (int i = 0; i < 3; ++i)array3[i] = s[pos++];
        array4[0] = (array3[0] & 0xFC) >> 2;
        array4[1] = ((array3[0] & 0x03) << 4) + ((array3[1] & 0xF0) >> 4);
        array4[2] = ((array3[1] & 0x0F) << 2) + ((array3[2] & 0xC0) >> 6);
        array4[3] = array3[2] & 0x3F;
        for (int i = 0; i < 4; ++i)ret.push_back(baseString[array4[i]]);
    }
    if (remain > 0) {
        for (int i = 0; i < remain; ++i)array3[i] = s[pos++];
        for (int i = remain; i < 4; ++i)array3[i] = 0;
        array4[0] = (array3[0] & 0xFC) >> 2;
        array4[1] = ((array3[0] & 0x03) << 4) + ((array3[1] & 0xF0) >> 4);
        array4[2] = ((array3[1] & 0x0F) << 2) + ((array3[2] & 0xC0) >> 6);
        array4[3] = array3[2] & 0x3F;
        for (int i = 0; i < remain + 1; ++i)ret.push_back(baseString[array4[i]]);
        for (int i = remain + 1; i < 4; ++i)ret.push_back('=');
    }
    return ret;
}

std::string ko::Base64::decode(const std::string& s) {
    unsigned char array3[3];
    unsigned char array4[4];
    unsigned group = s.length() / 4;
    const unsigned remain = s.length() - 4 * group;
    int pos = 0;
    std::string ret;
    ret.reserve(3 * group);
    assert(remain == 0);
    for (int g = 0; g < group; ++g) {
        for (int i = 0; i < 4; ++i)array4[i] = baseString.find(s[pos++]);
        array3[0] = (array4[0] << 2) + ((array4[1] & 0x30) >> 4);
        array3[1] = ((array4[1] & 0xf) << 4) + ((array4[2] & 0x3c) >> 2);
        array3[2] = ((array4[2] & 0x3) << 6) + array4[3];
        if (array4[2] == 255)ret.push_back(array3[0]);
        else if (array4[3] == 255) {
            ret.push_back(array3[0]);
            ret.push_back(array3[1]);
        }
        else {
            ret.push_back(array3[0]);
            ret.push_back(array3[1]);
            ret.push_back(array3[2]);
        }
    }
    return ret;
}