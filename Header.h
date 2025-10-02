#pragma once

#include <CDynamic.h>
#include <CSpoofer.h>
#include <CFunc.hpp>

#ifndef _DEBUG
#pragma comment(lib, "SafeDynamic.lib")
#else
#pragma comment(lib, "SafeDynamicD.lib")
#endif