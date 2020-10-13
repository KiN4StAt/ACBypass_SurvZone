#include <Windows.h>
#include <psapi.h>
#include "MinHook.h"
#include "BitStream.h"
#include "RakClient.h"
#include "resource.h"
#ifdef _DEBUG
#pragma comment(lib, "libMinHook-x86-v141-mtd.lib")
#elif _MD_RELEASE
#pragma comment(lib, "libMinHook-x86-v141-md.lib")
#else
#pragma comment(lib, "libMinHook-x86-v141-mt.lib")
#endif

enum SampVersion {
	SAMP_UNKNOWN = -1,

	SAMP_0_3_7_R1 = 0,
	SAMP_0_3_7_R3_1,
	SAMP_0_3_7_R4,
};

SampVersion sampVer;

DWORD HOOKREADMEM;
DWORD HOOKEXITREADMEM;
DWORD READMEMFUNC;
DWORD SAMPHMODULE;

HMODULE hSAMPModule;
HMODULE hGTAModule;

DWORD dwSampModule;
DWORD dwGTAModule;

unsigned char* ClearSAMPModule = nullptr;
unsigned char* ClearGTAModule = nullptr;
bool isHooked = false;
DWORD hkExitRPC = 0;
DWORD hkExitRPC2 = 0;

typedef void(__cdecl* CTimer_Update)();
typedef bool(__fastcall* RakPeer_Send)(void*, void*, BitStream*, int, int, int, int, __int16, int);
typedef bool(__fastcall* RakPeer_RPC)(void*, void*, int*, BitStream*, int, int, int, int, __int16, int, int, int, int, int);

RakPeer_Send fpSend = NULL;
RakPeer_RPC fpRPC = NULL;
CTimer_Update fpCTimer_Update = NULL;

bool __fastcall HOOK_RakPeer_RPC(void* dis, void* EDX, int* uniqueID, BitStream* parameters, int a4, int a5, int a6, int a7, __int16 a8, int a9, int a10, int a11, int a12, int a13) {
	if (*uniqueID == 25) {
		INT32 iVersion; UINT8 byteMod; UINT8 byteNicknameLen;
		UINT32 uiClientChallengeResponse;
		UINT8 byteAuthKeyLen;
		parameters->Read(iVersion);
		parameters->Read(byteMod);
		parameters->Read(byteNicknameLen);
		char* nickname = new char[byteNicknameLen + 1];
		nickname[byteNicknameLen] = 0;
		parameters->Read(nickname, byteNicknameLen);
		parameters->Read(uiClientChallengeResponse);
		parameters->Read(byteAuthKeyLen);
		char* authKey = new char[byteAuthKeyLen + 1];
		authKey[byteAuthKeyLen] = 0;
		parameters->Read(authKey, byteAuthKeyLen);
		parameters->SetWriteOffset(parameters->GetReadOffset());
		parameters->Write(static_cast<UINT8>(strlen("0.3.7-R3")));
		parameters->Write("0.3.7-R3", strlen("0.3.7-R3"));
	}
	return fpRPC(dis, EDX, uniqueID, parameters, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
}

char readMemory(int address, unsigned __int16 readSize)
{
	char result = 0;
	int i = 0;
	if (readSize)
	{
		do
			result ^= *(BYTE*)(i++ + address) & 0xCC;
		while (i != readSize);
	}
	return result;
}

void HandleRPCPacketFunc(unsigned char id, RPCParameters* rpcParams, void(*callback) (RPCParameters*)) {
	if (id == RPCEnumeration::RPC_ClientCheck) {
		BitStream bs(rpcParams->input, rpcParams->numberOfBitsOfData / 8, false);
		#pragma pack(push, 1)
		struct CCheck {
			unsigned __int8 requestType;
			unsigned __int32 arg;
			unsigned __int16 offset, readSize;
		};
		#pragma pack(pop)
		CCheck* data = reinterpret_cast<CCheck*>(rpcParams->input);
		if (data->readSize > 256u || data->readSize < 2u || data->offset > 256u) return;
		unsigned __int8 result = 0;
		switch (data->requestType) {
		case 0x5:
			if (data->arg >= 0x400000 && data->arg <= 0x856E00) {
				result = readMemory(data->arg + data->offset - dwGTAModule + reinterpret_cast<DWORD>(ClearGTAModule), data->readSize);
			}
			break;
		case 0x45:
		{
			if (data->arg <= 0xC3500) {
				result = readMemory(data->arg + data->offset + reinterpret_cast<DWORD>(ClearSAMPModule), data->readSize);
			}
		}
			break;
		default:
			callback(rpcParams);
			return;
		}
		BitStream sendBS;
		sendBS.Write(data->requestType);
		sendBS.Write(data->arg);
		sendBS.Write(result);
		int sendID = id;
		#pragma pack(push, 1)
		struct CNetGameR1 {
			char				junk[0x3C9];
			RakClientInterface* m_pRakClient;
		};
		#pragma pack(pop)
		RakClientInterface* pRak = (*reinterpret_cast<CNetGameR1**>(dwSampModule + 0x21A0F8))->m_pRakClient;
		pRak->RPC(&sendID, &sendBS, PacketPriority::HIGH_PRIORITY, PacketReliability::RELIABLE_ORDERED, 0u, false);
		return;
	}
	else {
		callback(rpcParams);
	}
}

uint8_t _declspec (naked) hook_handle_rpc_packet(void)
{
	static RPCParameters* pRPCParams = nullptr;
	static RPCNode* pRPCNode = nullptr;

	__asm pushad;
	__asm mov pRPCParams, eax;
	__asm mov pRPCNode, edi;

	HandleRPCPacketFunc(pRPCNode->uniqueIdentifier, pRPCParams, pRPCNode->staticFunctionPointer);

	if (isHooked == false) {
		__asm popad;
		__asm add esp, 4 // overwritten code
	}
	__asm jmp hkExitRPC;
}
uint8_t _declspec (naked) hook_handle_rpc_packet2(void)
{
	static RPCParameters* pRPCParams = nullptr;
	static RPCNode* pRPCNode = nullptr;

	__asm pushad;
	__asm mov pRPCParams, ecx;
	__asm mov pRPCNode, edi;

	HandleRPCPacketFunc(pRPCNode->uniqueIdentifier, pRPCParams, pRPCNode->staticFunctionPointer);

	__asm popad;
	__asm jmp hkExitRPC2;
}

MH_STATUS MH_CreateAndEnableHook(DWORD dwTargetAddress, LPVOID pDetour, LPVOID* ppOriginal) {
	MH_CreateHook(reinterpret_cast<LPVOID>(dwTargetAddress), pDetour, ppOriginal);
	return MH_EnableHook(reinterpret_cast<LPVOID>(dwTargetAddress));
}

__declspec(naked) void HK_ReadMemory(void) {
	static unsigned int address = 0;
	__asm {
		pushad
		mov address, eax
	}
	address += reinterpret_cast<DWORD>(ClearGTAModule) - dwGTAModule;
	static DWORD dwTmp = dwSampModule + READMEMFUNC;
	static DWORD retjmp = dwSampModule + HOOKEXITREADMEM;
	__asm {
		popad
		mov eax, address
		push eax
		call dwTmp
		jmp retjmp
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
		MH_Initialize();

		DWORD oldProt;
		MODULEINFO SAMPmoduleInfo;
		hSAMPModule = GetModuleHandle(L"samp.dll");
		hGTAModule = GetModuleHandle(L"gta_sa.exe");
		dwSampModule = reinterpret_cast<DWORD>(hSAMPModule);
		dwGTAModule = reinterpret_cast<DWORD>(hGTAModule);
		if (hSAMPModule == NULL || hGTAModule == NULL) return FALSE;

		GetModuleInformation(GetCurrentProcess(), hSAMPModule, &SAMPmoduleInfo, sizeof(SAMPmoduleInfo));

		switch (reinterpret_cast<DWORD>(SAMPmoduleInfo.EntryPoint) - dwSampModule) {
		case 0x31DF13:	sampVer = SampVersion::SAMP_0_3_7_R1; break;
		case 0xCC4D0:	sampVer = SampVersion::SAMP_0_3_7_R3_1; break;
		case 0xCBCB0:	sampVer = SampVersion::SAMP_0_3_7_R4; break;
		default:		return FALSE;
		}
		if (sampVer == SampVersion::SAMP_0_3_7_R1) {
			ClearSAMPModule = reinterpret_cast<unsigned char*>(LockResource(LoadResource(hModule, FindResourceW(hModule, MAKEINTRESOURCEW(IDR_DLL_FILE1), L"DLL_FILE"))));

			if (*reinterpret_cast<BYTE*>(dwSampModule + 0x3743D) == 0xE9) {
				isHooked = true;
				hkExitRPC = *reinterpret_cast<UINT32*>(dwSampModule + 0x3743D + 1);
			}
			else {
				hkExitRPC = dwSampModule + 0x37443;
			}
			if (*reinterpret_cast<BYTE*>(dwSampModule + 0x373C9) == 0xE9) {
				hkExitRPC2 = *reinterpret_cast<UINT32*>(dwSampModule + 0x373C9 + 1);
			}
			else {
				hkExitRPC2 = dwSampModule + 0x37451;
			}
			MH_CreateAndEnableHook(dwSampModule + 0x3743D, &hook_handle_rpc_packet, NULL);
			MH_CreateAndEnableHook(dwSampModule + 0x373C9, &hook_handle_rpc_packet2, NULL);
			MH_CreateAndEnableHook(dwSampModule + 0x36C30, &HOOK_RakPeer_RPC, reinterpret_cast<LPVOID*>(&fpRPC));
		}
		else {
			switch (sampVer) {
			case SampVersion::SAMP_0_3_7_R3_1:
				{
					HOOKREADMEM = 0x11A3F;
					HOOKEXITREADMEM = 0x11A44;
					READMEMFUNC = 0xE740;
					SAMPHMODULE = 0x26E880;
				}
				break;
			case SampVersion::SAMP_0_3_7_R4:
				{
					HOOKREADMEM = 0x11D6F;
					HOOKEXITREADMEM = 0x11D74;
					READMEMFUNC = 0xEA50;
					SAMPHMODULE = 0x26E9B0;
				}
				break;
			}
			ClearSAMPModule = new unsigned char[SAMPmoduleInfo.SizeOfImage];
			memcpy(ClearSAMPModule, reinterpret_cast<void*>(dwSampModule), SAMPmoduleInfo.SizeOfImage);
			VirtualProtect(reinterpret_cast<void*>(dwSampModule + HOOKREADMEM - 1), 6, PAGE_EXECUTE_READWRITE, &oldProt);

			*reinterpret_cast<unsigned char*>(dwSampModule + HOOKREADMEM - 1) = 0x90;
			MH_CreateAndEnableHook(dwSampModule + HOOKREADMEM, &HK_ReadMemory, NULL);

			VirtualProtect(reinterpret_cast<void*>(dwSampModule + HOOKREADMEM - 1), 6, oldProt, &oldProt);

			VirtualProtect(reinterpret_cast<void*>(dwSampModule + SAMPHMODULE), 4, PAGE_EXECUTE_READWRITE, &oldProt);
			*reinterpret_cast<HMODULE*>(dwSampModule + SAMPHMODULE) = reinterpret_cast<HMODULE>(ClearSAMPModule);
			VirtualProtect(reinterpret_cast<void*>(dwSampModule + SAMPHMODULE), 4, oldProt, &oldProt);
		}

		// Copying GTA Module anyway
		MODULEINFO GTAmoduleInfo;
		GetModuleInformation(GetCurrentProcess(), hGTAModule, &GTAmoduleInfo, sizeof(GTAmoduleInfo));
		ClearGTAModule = new unsigned char[GTAmoduleInfo.SizeOfImage];
		memcpy(ClearGTAModule, reinterpret_cast<void*>(dwGTAModule), GTAmoduleInfo.SizeOfImage);
	}
    return TRUE;
}