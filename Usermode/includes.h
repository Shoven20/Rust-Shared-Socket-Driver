#pragma once
#define M_PI 3.14159265359
#include <Windows.h>
#include <iostream>
#include <chrono>
#include <time.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <process.h>
#include <sstream>
#include <inttypes.h>
#include <dwmapi.h>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <stdexcept>
#include <tchar.h>
#include <array>
#include <cstdlib>
#include <mutex>
#include <atlsecurity.h> 
#include <strsafe.h> 
#include <shellapi.h>
#include <iomanip> 
#include <random>
#include <vector>
#include <d3d9.h>
#include <D3dx9tex.h>

#pragma comment(lib,"d3d9.lib")
#pragma comment(lib, "D3dx9")

#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <cryptopp/ccm.h>

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "rpcrt4.lib")

#include "ImGui/imgui_impl_win32.h"
#include "ImGui/imgui_impl_dx9.h"
#include "ImGui/imgui.h"

#include "discord_rpc.h"
#include "discord_register.h"

#include "XorStr.h"
#include "Mapper.h"
#include "Driver.h"
#include "DirectX.h"
#include "LogoBytes.h"
#include "Helpers.h"
#include "Settings.h"
#include "KeyAuth.h"

using namespace KeyAuth;