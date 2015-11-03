#include "interface.h"

bool rsa_public_encrpyt_withkey(const std::string& publickey, const std::string& srcdata, std::string& dstdata)
{
	std::cout<<"1"<<std::endl;
	return true;
}

bool rsa_public_encrypt(const std::string& srcdata, const std::string& password, std::string& dstdata, std::string& privatekeyout)
{
	std::cout<<"2"<<std::endl;
	return true;
}

bool rsa_private_decrypt(const std::string& privatekey, const std::string& passwordk,  const std::string& srcdata, std::string& dstdata)
{
	std::cout<<"3"<<std::endl;
	return true;
}

std::string test( std::string str )
{	
	return str + " : hello";
}
