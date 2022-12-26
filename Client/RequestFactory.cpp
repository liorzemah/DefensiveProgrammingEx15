#include "RequestFactory.h"

const std::unordered_map<RequestCode, std::function<void(void)>> RequestFactory::REQUEST_HANDLERS =
{
	{RequestCode::REQUEST_REGISTRATION, HandleRequestRegistration},
	{RequestCode::REQUEST_SEND_PUBLIC_KEY, HandleRequestRegistration},
	{RequestCode::REQUEST_RECONNECT, HandleRequestRegistration},
	{RequestCode::REQUEST_SEND_FILE, HandleRequestRegistration},
	{RequestCode::REQUEST_VALID_CRC, HandleRequestRegistration},
	{RequestCode::REQUEST_INVALID_CRC_RETRY, HandleRequestRegistration},
	{RequestCode::REQUEST_INVALID_CRC_FINISH, HandleRequestRegistration}
};

void RequestFactory::HandleRequestRegistration()
{

}
