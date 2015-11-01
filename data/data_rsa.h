#ifndef  __DATA_RSA_H
#define  __DATA_RSA_H

#include <string>

namespace datactl{
class DataRsa {
public:
	DataRsa();
	~DataRsa();

public:
	std::string private_key();
	void private_key(const std::string& key);
	std::string public_key();
	void public_key(const std::string& key);
	std::string pass_word();
	void pass_word(const std::string& pw);
	int getSecdataLen();
	bool generc_key(const std::string& password);

	bool data_encrypt(bool ispublic, const std::string& srcData, std::string& dstData);
	bool data_decrypt(bool ispublic, const std::string& srcData, std::string& dstData);
protected:
	bool private_encrypt(const std::string& srcData, std::string& dstData);
	bool private_decrypt(const std::string& srcData, std::string& dstData);
	bool public_encrypt(const std::string& srcData, std::string& dstData);
	bool public_decrypt(const std::string& srcData, std::string& dstData);
private:
	std::string privatekey;
	std::string publickey;
	std::string password;
	int         secdata_len;
};


}

#endif
