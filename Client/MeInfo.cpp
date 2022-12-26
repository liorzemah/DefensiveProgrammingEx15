#include "MeInfo.hpp"
#include <sstream>
#include "Base64.h"

const std::string MeInfo::ME_FILE = "me.info";

// Read from file
MeInfo::MeInfo()
{
	std::ifstream infile(ME_FILE);
	if (!infile.is_open())
	{
		throw std::invalid_argument("File " + ME_FILE + " not exists");
	}
	std::array<std::string, 3> lines;
	std::string line;
	int i = 0;
	while (i < 3 && std::getline(infile, line))
	{
		lines[i++] = line;
	}

	if (i < 3)
	{
		throw std::invalid_argument(ME_FILE + " contains less than 3 lines");
	}
	if (lines[0].size() > NAME_SIZE)
	{
		throw std::invalid_argument("First line in " + ME_FILE + " represent client name that suppose contains less than 255 letters");
	}
	std::copy(lines[0].begin(), lines[0].end(), std::begin(m_name.name));

	if (lines[1].size() != 32)
	{
		throw std::invalid_argument("Second line in " + ME_FILE + " represent uuid that suppose contains 32 hex letters");

	}
	for (int i = 0; i < 32; i += 2)
	{
		std::stringstream octet; 
		octet << lines[1][i] << lines[1][i + 1];
		m_uuid.uuid[i / 2] = std::stoi(octet.str(), nullptr, 16);
	}
	m_rsa = std::make_shared<RSAPrivateWrapper>(Base64::Decode(lines[2]));
}

// Create object and save to file
MeInfo::MeInfo(const ClientName& name, const ClientID& uuid) : m_name(name), m_uuid(uuid), m_rsa(std::make_shared<RSAPrivateWrapper>())
{
	std::ofstream infile(ME_FILE);
	infile << m_name << "\n" << m_uuid << "\n" << Base64::Encode(m_rsa->getPrivateKey());
	SaveRsaPrivateKey();
}

void MeInfo::SaveRsaPrivateKey()
{
	if (m_rsa == nullptr)
	{
		throw std::runtime_error("Tring to save private key that not been created yet");
	}

	static const std::string PRIVATE_KEY_FILE = "priv.key";
	const auto rasPrivateKey = m_rsa->getPrivateKey();
	std::ofstream infile(PRIVATE_KEY_FILE);
	infile << m_rsa->getPrivateKey();
}

