//#include "interface.h"

#include <iostream>
#include <string>
bool rsa_public_encrpyt_withkey(const std::string& publickey, const std::string& srcdata, std::string& dstdata)
{
	std::cout<<"1"<<std::endl;
	return true;
}

bool rsa_public_encrypt(const std::string& srcdata, std::string& dstdata, std::string& privatekey, std::string& password)
{
	std::cout<<"2"<<std::endl;
	return true;
}

bool rsa_private_encrypt(const std::string& privatekey, const std::string& passwordk,  const std::string& srcdata, std::string& dstdata)
{
	std::cout<<"3"<<std::endl;
	return true;
}


int test()
{	
	return 100;
}
