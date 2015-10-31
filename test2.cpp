#include <string>
#include <iostream>

#include "data_rsa.h"


int main()
{
	std::string data="abcdefghijklmnopqrstuvwxyz0123456789";

	datactl::DataRsa enc_rsa;

	///rsa.password("123456");
	enc_rsa.generc_key("123456");
	std::string password = enc_rsa.pass_word();
	std::string publickey = enc_rsa.public_key();
	std::string privatekey = enc_rsa.private_key();

	std::string secData = "";

	if( !enc_rsa.data_encrypt(true, data, secData) )
	{
		std::cout<<"error to encruypt data using public key"<<std::endl;
		return -1;
	}
	std::cout<<"the secrate data: "<<std::endl;
	std::cout<<secData<<std::endl;
	std::cout<<"===================================="<<std::endl;

	datactl::DataRsa dec_rsa;
	dec_rsa.pass_word(password);
	dec_rsa.private_key(privatekey);

	std::string dData = "";
	if(!dec_rsa.data_decrypt(false, secData, dData))
	{
		std::cout<<"error to decrytp data using private key"<<std::endl;
		return -1;
	}
	std::cout<<"the data is: " <<std::endl;
	std::cout<<dData<<std::endl;
	std::cout<<"================================"<<std::endl;
	
	return 0;
}
