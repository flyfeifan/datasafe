#ifndef  __DATA_CTL_H
#define  __DATA_CTL_H

#include <string>

namespace datactl{
class DataCtl {
public:
	DataCtl();
	~DataCtl();

public:
	std::string private_key();
	void private_key(const std::string& key);
	std::string public_key();
	void public_key(const std::string& key);
	std::string password();
	void password(const std::string& pw);

	bool generc_key(const std::string& password);

	bool data_encrypt(bool publickey, const std::stirng& stcData, std::string& dstData);
	bool data_decrypt(bool publickey, const std::string& srcData, std::string& dstData);
protected:
	bool private_encrypt(const std::stirng& stcData, std::string& dstData);
	bool private_decrypt(const std::stirng& stcData, std::string& dstData);
	bool public_encrypt(const std::stirng& stcData, std::string& dstData);
	bool public_decrypt(const std::stirng& stcData, std::string& dstData);
private:
	std::string private_key;
	std::string public_key;
	std::string password;
};


}







#endif
