#include <iostream>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "data_rsa.h"

namespace datactl{

DataRsa::DataRsa()
{
	privatekey.clear();
	publickey.clear();
	secdata_len = 0;

}

DataRsa::~DataRsa()
{

}

std::string DataRsa::private_key()
{
	return privatekey;
}

void DataRsa::private_key(const std::string& key)
{
	privatekey = key;
}

std::string DataRsa::public_key()
{
	return publickey;
}

void DataRsa::public_key(const std::string& key)
{
	publickey = key;
}

std::string DataRsa::pass_word()
{
	return password;
}

void DataRsa::pass_word(const std::string& pw)
{
	password = pw;
}

int DataRsa::getSecdataLen()
{
	if( !publickey.empty() && ( secdata_len <= 0 ))
	{
			OpenSSL_add_all_algorithms(); 
			BIO* pBio = BIO_new( BIO_s_mem() );
			BIO_write(pBio, publickey.c_str(), publickey.length());
			RSA* public_rsa = PEM_read_bio_RSAPublicKey(pBio, NULL, NULL, NULL);
			BIO_free_all(pBio);

			if( NULL == public_rsa )
			{
					RSA_free(public_rsa);
					CRYPTO_cleanup_all_ex_data();
					return -1;
			}

			secdata_len = RSA_size(public_rsa);
			RSA_free(public_rsa);
			CRYPTO_cleanup_all_ex_data();


	}
	else if( !privatekey.empty() && !password.empty() && (secdata_len <= 0 ))
	{
			OpenSSL_add_all_algorithms();
			BIO *pBio = BIO_new( BIO_s_mem() );
			BIO_write(pBio, privatekey.c_str(), privatekey.length());

			char pass[512];
			memset(pass, '\0', 512);
			snprintf(pass, 512, "%s", password.c_str());
			RSA* private_rsa = PEM_read_bio_RSAPrivateKey(pBio, NULL, NULL, (unsigned char*)pass );
			BIO_free_all(pBio);

			if( NULL == private_rsa ){
					RSA_free(private_rsa); 
					CRYPTO_cleanup_all_ex_data();
					return -1;
			}
			secdata_len =  RSA_size(private_rsa);
			RSA_free(private_rsa); 
			CRYPTO_cleanup_all_ex_data();		
	}
	return secdata_len;
}

bool DataRsa::generc_key(const std::string& password)
{
	privatekey.clear();
	publickey.clear();
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
	publickey.assign(buffer);
	memset(buffer, '\0', 2048);
	//get private key
	BIO* bp2 = BIO_new( BIO_s_mem() );
	if( !bp2 )
		return false;
	char pass[512];
	memset(pass, '\0', 512);
	snprintf(pass, 512, "%s", password.c_str());
	if( PEM_write_bio_RSAPrivateKey(bp, rsa, EVP_des_cfb64(), (unsigned char*)pass, password.length(), NULL, NULL) != 1 )
		return false;

	BIO_read(bp2, buffer, sizeof(buffer));
	BIO_free_all( bp2 );
	privatekey.assign(buffer);
	RSA_free(rsa);
	return true;

}

bool DataRsa::data_encrypt(bool publickey, const std::string& srcData, std::string& dstData)
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

bool DataRsa::data_decrypt(bool publickey, const std::string& srcData, std::string& dstData)
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

bool DataRsa::private_encrypt(const std::string& srcData, std::string& dstData)
{
	if( privatekey.empty() || password.empty() || srcData.empty() )
		return false;
	
	OpenSSL_add_all_algorithms();
	BIO *pBio = BIO_new( BIO_s_mem() );
	BIO_write(pBio, privatekey.c_str(), privatekey.length());
	
	char pass[512];
	memset(pass, '\0', 512);
	snprintf(pass, 512, "%s", password.c_str());
	RSA* private_rsa = PEM_read_bio_RSAPrivateKey(pBio, NULL, NULL, (unsigned char*)pass );
	BIO_free_all(pBio);
	
	if( NULL == private_rsa ){
		RSA_free(private_rsa); 
		CRYPTO_cleanup_all_ex_data();
		return false;
	}
	
	secdata_len =  RSA_size(private_rsa);
	int buf_len = secdata_len -11;
	char* dst_buff = new char[secdata_len + 1 ];
	memset(dst_buff, '\0', secdata_len + 1);

	int src_pos = 0;
	while( src_pos < srcData.length() )
	{
		std::string src_buff = srcData.substr(src_pos, buf_len);
		src_pos += buf_len;
		int res = RSA_private_encrypt(buf_len, (const unsigned char*)src_buff.c_str(), (unsigned char*)dst_buff, private_rsa, RSA_PKCS1_PADDING);
		if(res != secdata_len )
		{
			delete[] dst_buff;
			RSA_free(private_rsa);
			CRYPTO_cleanup_all_ex_data();
			 return false;
		}
	//	int l = strlen(dst_buff);
		dstData.append(dst_buff, res);
		memset(dst_buff, '\0', secdata_len + 1);
	}
	delete[] dst_buff;
	RSA_free(private_rsa);
	CRYPTO_cleanup_all_ex_data();
	return true;
}

bool DataRsa::private_decrypt(const std::string& srcData, std::string& dstData)
{
	if (privatekey.empty() || password.empty() || srcData.empty() )
		return false;
	OpenSSL_add_all_algorithms(); 
	BIO* pBio = BIO_new( BIO_s_mem() );
	BIO_write(pBio, privatekey.c_str(), privatekey.length());
	
	char pass[512];
	memset(pass, '\0', 512);
	snprintf(pass, 512, "%s", password.c_str());
	RSA* private_rsa = PEM_read_bio_RSAPrivateKey(pBio, NULL, NULL, (unsigned char*)pass);
	BIO_free_all(pBio);

	if( NULL == private_rsa )
	{
		RSA_free(private_rsa);
		CRYPTO_cleanup_all_ex_data();
		return false;
	}
	
	secdata_len = RSA_size(private_rsa);
	if (srcData.length() % secdata_len != 0)
	{
		RSA_free(private_rsa);
		CRYPTO_cleanup_all_ex_data();
		return false;
	}
	
	char* dst_buff = new char[secdata_len + 1];
	memset(dst_buff, '\0', secdata_len + 1);
	int pos = 0;
	while( pos < srcData.length() )
	{
		std::string src_buff = srcData.substr(pos, secdata_len);
		pos += secdata_len;
		int ret = RSA_private_decrypt(secdata_len, (const unsigned char*)src_buff.c_str(), (unsigned char*)dst_buff, private_rsa, RSA_PKCS1_PADDING);
		if(ret < 0 )
		{
			delete[] dst_buff;
			RSA_free(private_rsa);
			CRYPTO_cleanup_all_ex_data();
			return false;
		}
		int l = strlen(dst_buff);
		dstData.append(dst_buff, l);
		memset(dst_buff, '\0', secdata_len + 1);
	}
	CRYPTO_cleanup_all_ex_data();
	delete[] dst_buff;
	return true;
}

bool DataRsa::public_encrypt(const std::string& srcData, std::string& dstData)
{
	if( publickey.empty() || srcData.empty() )
		return false;
	
	OpenSSL_add_all_algorithms(); 
	BIO* pBio = BIO_new( BIO_s_mem() );
	BIO_write(pBio, publickey.c_str(), publickey.length());
	RSA* public_rsa = PEM_read_bio_RSAPublicKey(pBio, NULL, NULL, NULL);
	BIO_free_all(pBio);
	
	if( NULL == public_rsa )
	{
		RSA_free(public_rsa);
		CRYPTO_cleanup_all_ex_data();
		return false;
	}
	
	secdata_len = RSA_size(public_rsa);
	int buf_len = secdata_len -11;
	
	char* dst_buff = new char[secdata_len + 1 ];
	memset(dst_buff, '\0', secdata_len + 1);
	
	int src_pos = 0;
	while( src_pos < srcData.length() )
	{
		std::string src_buff = srcData.substr(src_pos, buf_len);
		src_pos += buf_len;
		int res = RSA_public_encrypt(buf_len, (const unsigned char*)src_buff.c_str(), (unsigned char*)dst_buff, public_rsa, RSA_PKCS1_PADDING);
		if(res != secdata_len )
		{
			delete[] dst_buff;
			RSA_free(public_rsa);
			CRYPTO_cleanup_all_ex_data();
			return false;
		}
		//int l = strlen(dst_buff);
		dstData.append(dst_buff, res);
		memset(dst_buff, '\0', secdata_len + 1);
	}
	delete[] dst_buff;
	RSA_free(public_rsa);
	CRYPTO_cleanup_all_ex_data();
	return true;
}

bool DataRsa::public_decrypt(const std::string& srcData, std::string& dstData)
{
	if ( publickey.empty() || srcData.empty() )
		return false;
	OpenSSL_add_all_algorithms(); 
	BIO* pBio = BIO_new( BIO_s_mem() );
	BIO_write(pBio, publickey.c_str(), publickey.length());
	RSA* public_rsa = PEM_read_bio_RSAPublicKey(pBio, NULL, NULL, NULL);
	BIO_free_all(pBio);

	if( NULL == public_rsa )
	{
		RSA_free(public_rsa);
		CRYPTO_cleanup_all_ex_data();
		return false;
	}
	
	secdata_len = RSA_size(public_rsa);
	if (srcData.length() % secdata_len != 0)
	{
		RSA_free(public_rsa);
		CRYPTO_cleanup_all_ex_data();
		return false;
	}
	
	char* dst_buff = new char[secdata_len + 1];
	memset(dst_buff, '\0', secdata_len + 1);
	int pos = 0;
	while( pos < srcData.length() )
	{
		std::string src_buff = srcData.substr(pos, secdata_len);
		pos += secdata_len;
		int ret = RSA_public_decrypt(secdata_len, (const unsigned char*)src_buff.c_str(), (unsigned char*)dst_buff, public_rsa, RSA_PKCS1_PADDING);
		if(ret < 0 )
		{
			delete[] dst_buff;
			RSA_free(public_rsa);
			CRYPTO_cleanup_all_ex_data();
			return false;
		}
		int l = strlen(dst_buff);
		dstData.append(dst_buff, l);
		memset(dst_buff, '\0', secdata_len + 1);
	}
	CRYPTO_cleanup_all_ex_data();
	delete[] dst_buff;
	return true;
}

}
