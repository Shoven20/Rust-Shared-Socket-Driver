#pragma once
#include <WinSock.h>
#include <cstdint>
#include <vector>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <string_view>
#include <cstdint>
#include <vector>
#include <chrono>

static SOCKET r_socket;
static DWORD r_pid;
static uint64_t exebase;

void initdrv();
void clean_socket();
SOCKET connect();
void close_socket(const SOCKET a_socket);
uint32_t read_memory(const SOCKET a_socket, uint32_t process_id, uintptr_t address, uintptr_t buffer, size_t size);
uint32_t write_memory(const SOCKET a_socket, uint32_t process_id, uintptr_t address, uintptr_t buffer, size_t size);
uint64_t process_base_address(const SOCKET a_socket, uint32_t exe_id);
uint64_t dll_oku(const SOCKET a_socket, uint32_t process_id, int module);
uint64_t clean_piddbcachetable(const SOCKET a_socket);
uint64_t clean_mmunloadeddrivers(const SOCKET a_socket);
std::uint32_t process_id(const std::string& name);

namespace driver {
	template <typename T>
	T read(const uintptr_t address)
	{
		T buffer{ };
		read_memory(r_socket, r_pid, address, uint64_t(&buffer), sizeof(T));

		return buffer;
	}

	template <typename T>
	void write(const uintptr_t address, const T& buffer)
	{
		write_memory(r_socket, r_pid, address, uint64_t(&buffer), sizeof(T));
	}

	static void readsize(const uintptr_t address, void* buffer, size_t size)
	{
		read_memory(r_socket, r_pid, address, uint64_t(buffer), size);
	}
}