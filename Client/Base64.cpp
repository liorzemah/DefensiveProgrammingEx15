#include "Base64.h"

const std::string Base64::BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool Base64::isBase64Letter(unsigned char c) 
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string Base64::Encode(const std::string& bytes) 
{
    // base 64 encoder, get string and encode it to base64 and present as string
    auto len = bytes.size();
    auto bytesArr = reinterpret_cast<const uint8_t*>(bytes.c_str());
    return Encode(bytesArr, len);
}

std::string Base64::Encode(const uint8_t* bytes, size_t len)
{
    // base 64 encoder, get array of bytes encode them to base64 and present as string
    std::string base64Str;
    int i = 0;
    int j = 0;
    uint8_t arrOf3[3];
    uint8_t arrOf4[4];

    while (len--)
    {
        arrOf3[i++] = *(bytes++);
        if (i == 3) {
            arrOf4[0] = (arrOf3[0] & 0xfc) >> 2;
            arrOf4[1] = ((arrOf3[0] & 0x03) << 4) + ((arrOf3[1] & 0xf0) >> 4);
            arrOf4[2] = ((arrOf3[1] & 0x0f) << 2) + ((arrOf3[2] & 0xc0) >> 6);
            arrOf4[3] = arrOf3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                base64Str += BASE64_CHARS[arrOf4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            arrOf3[j] = '\0';

        arrOf4[0] = (arrOf3[0] & 0xfc) >> 2;
        arrOf4[1] = ((arrOf3[0] & 0x03) << 4) + ((arrOf3[1] & 0xf0) >> 4);
        arrOf4[2] = ((arrOf3[1] & 0x0f) << 2) + ((arrOf3[2] & 0xc0) >> 6);
        arrOf4[3] = arrOf3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            base64Str += BASE64_CHARS[arrOf4[j]];

        while ((i++ < 3))
            base64Str += '=';
    }

    return base64Str;
}
std::string Base64::Decode(const std::string& base64Str)
{
    // base 64 decoder, get encoded string (in base64 format) decode it and present as string
    int in_len = base64Str.size();
    int i = 0;
    int j = 0;
    int k = 0;
    uint8_t arrOf3[3];
    uint8_t arrOf4[4];
    std::string decodedStr;

    while (in_len-- && (base64Str[k] != '=') && isBase64Letter(base64Str[k]))
    {
        arrOf4[i++] = base64Str[k]; k++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                arrOf4[i] = BASE64_CHARS.find(arrOf4[i]);

            arrOf3[0] = (arrOf4[0] << 2) + ((arrOf4[1] & 0x30) >> 4);
            arrOf3[1] = ((arrOf4[1] & 0xf) << 4) + ((arrOf4[2] & 0x3c) >> 2);
            arrOf3[2] = ((arrOf4[2] & 0x3) << 6) + arrOf4[3];

            for (i = 0; (i < 3); i++)
                decodedStr += arrOf3[i];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 4; j++)
            arrOf4[j] = 0;

        for (j = 0; j < 4; j++)
            arrOf4[j] = BASE64_CHARS.find(arrOf4[j]);

        arrOf3[0] = (arrOf4[0] << 2) + ((arrOf4[1] & 0x30) >> 4);
        arrOf3[1] = ((arrOf4[1] & 0xf) << 4) + ((arrOf4[2] & 0x3c) >> 2);
        arrOf3[2] = ((arrOf4[2] & 0x3) << 6) + arrOf4[3];

        for (j = 0; (j < i - 1); j++) decodedStr += arrOf3[j];
    }

    return decodedStr;
}
