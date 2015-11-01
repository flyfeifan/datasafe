%module interface

%{
#include <iostream>
#include <string>
%}
/*
extern bool rsa_public_encrpyt_withkey(const std::string& publickey, const std::string& srcdata, std::string& dstdata);
extern bool rsa_public_encrypt(const std::string& srcdata, std::string& dstdata, std::string& privatekey, std::string& password);
extern bool res_private_encrypt(const std::string& privatekey, const std::string& passwordk,  const std::string& srcdata, std::string& dstdata);
*/
extern int test_interface();
