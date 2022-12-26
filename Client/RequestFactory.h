#pragma once
#include <unordered_map>
#include <functional>
#include "Protocol.h"

class RequestFactory
{
	static const std::unordered_map<RequestCode, std::function<void(void)>> REQUEST_HANDLERS;

	static void HandleRequestRegistration();
public:
	RequestFactory() = default;

};

