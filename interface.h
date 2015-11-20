#include <string>
#include <iostream>
#include <data_rsa.h>

bool rsa_public_encrypt_withkey(const std::string& publickey, const std::string& srcdata, std::string& dstdata);

bool rsa_public_encrypt(const std::string& srcdata,const std::string& password,  std::string& dstdata, std::string& privatekeyout);

bool rsa_private_decrypt(const std::string& privatekey, const std::string& password,  const std::string& srcdata, std::string& dstdata);
// TODO 2
bool rsa_private_encrypt_withkey(const std::string& privatekey, const std::string& password, const std::string& srcdata, std::string& dstdata);

bool rsa_private_encrypt(const std::string& srcdata,const std::string& password,  std::string& dstdata, std::string& publickeyout);

bool rsa_public_decrypt(const std::string& publickey, const std::string& srcdata, std::string& dstdata);

bool rsa_getkes(const std::string& password, std::string& privatekeyout, std::string& publickeyout);

std::string test(std::string);
