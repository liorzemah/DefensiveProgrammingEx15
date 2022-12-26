#pragma once
#include <string>
#include <stdexcept>

class FatalException : public std::exception
{
public:
	FatalException(const std::string& error) : m_error(error)
	{
	}

	const char* what() const noexcept override
	{
		return m_error.c_str();
	}

private:
	std::string m_error;
};
