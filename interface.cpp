#include "interface.h"

bool rsa_public_encrypt_withkey(const std::string& publickey, const std::string& srcdata, std::string& dstdata)
{
	datactl::DataRsa enc_rsa;
	enc_rsa.public_key(publickey);
	if( !enc_rsa.data_encrypt(true, srcdata, dstdata) )
		return false;
	return true;
}

bool rsa_public_encrypt(const std::string& srcdata, const std::string& password, std::string& dstdata, std::string& privatekeyout)
{
	datactl::DataRsa enc_rsa;
	if( !enc_rsa.generc_key(password) )
		return false;
	privatekeyout=enc_rsa.private_key();

	if( !enc_rsa.data_encrypt(true, srcdata, dstdata) )
		return false;
	return true;
}

bool rsa_private_decrypt(const std::string& privatekey, const std::string& password,  const std::string& srcdata, std::string& dstdata)
{
	datactl::DataRsa dec_rsa;
	dec_rsa.private_key(privatekey);
	dec_rsa.pass_word(password);
	if( !dec_rsa.data_decrypt(false, srcdata, dstdata) )
		return false;
	return true;
}

bool rsa_private_encrypt_withkey(const std::string& privatekey, const std::string& password, const std::string& srcdata, std::string& dstdata)
{
	datactl::DataRsa enc_rsa;
	enc_rsa.private_key(privatekey);
	enc_rsa.pass_word(password);

	if( !enc_rsa.data_encrypt(false, srcdata, dstdata) )
		return false;
	return true;
}

bool rsa_private_encrypt(const std::string& srcdata,const std::string& password,  std::string& dstdata, std::string& publickeyout)
{
	datactl::DataRsa enc_rsa;
	if( !enc_rsa.generc_key(password) )
		return false;
	publickeyout=enc_rsa.public_key();
	
	if( !enc_rsa.data_encrypt(false, srcdata, dstdata) )
		return false;
	return true;
}

bool rsa_public_decrypt(const std::string& publickey, const std::string& srcdata, std::string& dstdata)
{
	datactl::DataRsa dec_rsa;
	dec_rsa.public_key(publickey);
	if( !dec_rsa.data_decrypt(true, srcdata, dstdata) )
		return false;
	return true;
}

bool rsa_getkes(const std::string& password, std::string& privatekeyout, std::string& publickeyout)
{
	datactl::DataRsa key_rsa;
	if( !key_rsa.generc_key(password))
		return false;
	publickeyout=key_rsa.public_key();
	privatekeyout=key_rsa.private_key();
	return true;
}

std::string test( std::string str )
{	
	return str + " : hello";
}
