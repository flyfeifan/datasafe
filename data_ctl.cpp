#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#inlcude "data_ctl.h"

namespace datactl{

DataCtl::DataCtl()
{
	private_key.clean();
	public_key.clean();

}

DataCtl::~DataCtl()
{

}

std::string DataCtl::private_key()
{
	return private_key;
}

void DataCtl::private_key(const std::string& key)
{
	private_key = key;
}

std::string DataCtl::public_key()
{
	return public_key;
}

void DataCtl::public_key(const std::string& key)
{
	public_key = key;
}

std::string DataCtl::password()
{
	return password;
}

void DataCtl::password(const std::string& pw)
{
	password = pw;
}

bool DataCtl::generc_key(const std::string& password)
{
	private_key.clean();
	public_key.clean();
	this->password = password;
	RSA* rsa = RSA_generate_key(1024, RSA_F4, NULL, NULL);
	if( !rsa )
		return false;
	
	char buffer[2048];
	memset(buffer, '\0', 2048);
	//get public key
	BIO *bp = BIO_new( BIO_s_mem() );
	if( !bp )
		return false;
	if ( PEM_write_bio_RSAPublicKey(bp, rsa) != 1)
		return false;
	
	BIO_read(bp, buffer, sizeof(buffer));
	BIO_free_all( bp );
	public_key.assign(buffer);
	memset(buffer, '\0', 2048);
	//get private key
	Bio bp2 = BIO_new( BIO_s_mem() );
	if( !bp2 )
		return false;
	if( PEM_write_bio_RSAPrivateKey(bp, rsa, EVP_des_cfb64(), password.c_str(), password.length(), NULL, NULL) != 1 )
		return false;

	BIO_read(bp2, buffer, sizeof(buffer));
	BIO_free_all( bp2 );
	private_key.assign(buffer);
	RSA_free(rsa);
	return true;

}

bool DataCtl::data_encrypt(bool publickey, const std::string& srcData, std::string& dstData)
{
	if( publickey)
	{
		return public_encrypt(srcData, dstData);
	}
	else
	{
		return private_encrypt(srcData, dstData);
	}
}

bool DataCtl::data_decrypt(bool publickey, const std::string& srcData, std::string& dstData)
{
	if( publickey )
	{
		return public_decrypt(srcData, dstData);
	}
	else
	{
		return private_decrypt(srcData, dstData);
	}
}

bool DataCtl::private_encrypt(const std::stirng& stcData, std::string& dstData)
{
	if( private_key.empty() || password.empty() )
		return false;
	
	OpenSSl_add_all_algorithms();
	BIO *pBio = BIO_new( BIO_s_mem() );
	BIO_write(bp, private_key.c_str(), private_key.length() * sizeof(char));
	RSA* rsaK = PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, passwd);



	return true;
}

bool DataCtl::private_decrypt(const std::stirng& stcData, std::string& dstData)
{
	if (private_key.empty() || pwssword.empty() )
		return false;
	return true;
}

bool DataCtl::public_encrypt(const std::stirng& stcData, std::string& dstData)
{
	if( public_key.empty() )
		return false;

	return true;
}

bool DataCtl::public_decrypt(const std::stirng& stcData, std::string& dstData)
{
	if ( public_key.empty() )
		return false;
	return true;
}


}
