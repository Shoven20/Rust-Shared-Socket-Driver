#include "Server.h"
#include "Sockets.h"
#include "Defs.h"
#include <ntstrsafe.h>
#include <ntddk.h>
#include <ntifs.h>
#include "includes.hpp"

static uint64_t handle_copy_memory(const PacketCopyMemory& packet)
{
	PEPROCESS dest_process = nullptr;
	PEPROCESS src_process = nullptr;
	SIZE_T return_size = 0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(packet.dest_process_id), &dest_process)))
	{
		return uint64_t(STATUS_INVALID_CID);
	}

	if (!NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(packet.src_process_id), &src_process)))
	{
		ObDereferenceObject(dest_process);

		return uint64_t(STATUS_INVALID_CID);
	}

	NTSTATUS status = MmCopyVirtualMemory(src_process, (void*)packet.src_address, dest_process, (void*)packet.dest_address, packet.size, UserMode, &return_size);

	ObDereferenceObject(dest_process);
	ObDereferenceObject(src_process);

	return uint64_t(status);
}

static uint64_t handle_get_base_address(const PacketGetBaseAddress& packet)
{
	PEPROCESS process = nullptr;
	NTSTATUS  status = PsLookupProcessByProcessId(HANDLE(packet.exe_id), &process);

	if (!NT_SUCCESS(status))
		return 0;

	const auto base_address = uint64_t(PsGetProcessSectionBaseAddress(process));
	ObDereferenceObject(process);

	return base_address;
}

static uint64_t handle_get_dll_address(const PacketGetBaseAddress& packet)
{
	PEPROCESS pProcess = NULL;
	UNICODE_STRING se;
	if (packet.name == 0) {
		RtlInitUnicodeString(&se, L"UnityPlayer.dll");
	}
	else {
		RtlInitUnicodeString(&se, L"GameAssembly.dll");
	}
	uint64_t result = 0;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)packet.process_id, &pProcess)))
	{
		PPEB pPeb = PsGetProcessPeb(pProcess);
		KAPC_STATE state;

		KeStackAttachProcess(pProcess, &state);
		for (PLIST_ENTRY pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink; result == 0 && pListEntry != &pPeb->Ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			if (RtlCompareUnicodeString(&pEntry->BaseDllName, &se, TRUE) == 0) {
				result = (uint64_t)pEntry->DllBase;
			}
		}

		KeUnstackDetachProcess(&state);
	}
	return result;
} // for rust /shrug

bool complete_request(const SOCKET client_connection, const uint64_t result)
{
	Packet packet{ };
	packet.header.magic = packet_magic;
	packet.header.type = PacketType::packet_completed;
	packet.data.completed.result = result;

	return send(client_connection, &packet, sizeof(packet), 0) != SOCKET_ERROR;
}

static uintptr_t get_kernel_address(const char* name, size_t& size) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG a_size = 0;
	ZwQuerySystemInformation(SystemModuleInformation, &a_size, 0, &a_size);

	PSYSTEM_MODULE_INFORMATION pModuleList;

	pModuleList = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, a_size);

	if (!pModuleList) {
		return 0;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, pModuleList, a_size, 0);

	ULONG i = 0;
	uintptr_t address = 0;

	for (i = 0; i < pModuleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE mod = pModuleList->Modules[i];

		address = uintptr_t(pModuleList->Modules[i].Base);
		size = uintptr_t(pModuleList->Modules[i].Size);
		if (strstr(mod.ImageName, name) != NULL)
			break;
	}

	ExFreePool(pModuleList);

	return address;
}

static uint64_t clean_piddb_cache() {
	PRTL_AVL_TABLE PiDDBCacheTable;

	size_t size;
	uintptr_t ntoskrnlBase = get_kernel_address("ntoskrnl.exe", size);
	PiDDBCacheTable = (PRTL_AVL_TABLE)dereference(find_pattern<uintptr_t>((void*)ntoskrnlBase, size, "\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x3d\x00\x00\x00\x00\x0f\x83", "xxx????x????x????xx"), 3);


	if (!PiDDBCacheTable) {
		return 0;
	}

	uintptr_t entry_address = uintptr_t(PiDDBCacheTable->BalancedRoot.RightChild) + sizeof(RTL_BALANCED_LINKS);

	piddbcache* entry = (piddbcache*)(entry_address);

	if (entry->TimeDateStamp == 0x57CD1415 || entry->TimeDateStamp == 0x5284EAC3) {
		entry->TimeDateStamp = 0x54EAC3;
		entry->DriverName = RTL_CONSTANT_STRING(L"monitor.sys");
	}
	ULONG count = 0;
	for (auto link = entry->List.Flink; link != entry->List.Blink; link = link->Flink, count++)
	{
		piddbcache* cache_entry = (piddbcache*)(link);

		(count, cache_entry->DriverName, cache_entry->TimeDateStamp, cache_entry->LoadStatus);
		if (cache_entry->TimeDateStamp == 0x57CD1415 || cache_entry->TimeDateStamp == 0x5284EAC3) {
			cache_entry->TimeDateStamp = 0x54EAC4 + count;
			cache_entry->DriverName = RTL_CONSTANT_STRING(L"monitor.sys");
		}
	}

	return 1;
}

static uint64_t clean_unloaded_drivers() {
	ULONG bytes = 0;
	auto status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes)
		return 0;

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status)) {
		ExFreePool(modules);
		return 0;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	uintptr_t ntoskrnlBase = 0;
	size_t ntoskrnlSize = 0;

	ntoskrnlBase = get_kernel_address("ntoskrnl.exe", ntoskrnlSize);

	ExFreePool(modules);

	if (ntoskrnlBase <= 0) {
		return 0;
	}

	auto mmUnloadedDriversPtr = find_pattern<uintptr_t>((void*)ntoskrnlBase, ntoskrnlSize, "\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");

	if (!mmUnloadedDriversPtr) {
		return 0;
	}

	uintptr_t mmUnloadedDrivers = dereference(mmUnloadedDriversPtr, 3);

	memset(*(uintptr_t**)mmUnloadedDrivers, 0, 0x7D0);

	return 1;
}

uint64_t handle_incoming_packet(const Packet& packet)
{
	switch (packet.header.type)
	{
	case PacketType::packet_copy_memory:
		return handle_copy_memory(packet.data.copy_memory);

	case PacketType::packet_get_base_address:
		return handle_get_base_address(packet.data.get_base_address);

	case PacketType::packet_get_dll_address:
		return handle_get_dll_address(packet.data.get_dll_address);

	case PacketType::packet_clean_piddbcachetable:
		return clean_piddb_cache();

	case PacketType::packet_clean_mmunloadeddrivers:
		return clean_unloaded_drivers();

	default:
		break;
	}

	return uint64_t(STATUS_NOT_IMPLEMENTED);
}