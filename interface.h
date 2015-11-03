#include <string>
#include <iostream>

bool rsa_public_encrpyt_withkey(const std::string& publickey, const std::string& srcdata, std::string& dstdata);
bool rsa_public_encrypt(const std::string& srcdata,const std::string& password,  std::string& dstdata, std::string& privatekeyout);
bool rsa_private_decrypt(const std::string& privatekey, const std::string& passwordk,  const std::string& srcdata, std::string& dstdata);

std::string test(std::string);
