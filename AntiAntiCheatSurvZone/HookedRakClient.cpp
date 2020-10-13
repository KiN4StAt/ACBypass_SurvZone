#include "HookedRakClient.h"
#include "dllmain.h"
#include <random>
#include <Windows.h>

#include <unordered_map>

std::unordered_map<unsigned int, unsigned char> AddrMap = {};

bool HookedRakClientInterface::RPC(int* uniqueID, BitStream *parameters, PacketPriority priority, PacketReliability reliability, char orderingChannel, bool shiftTimestamp)
{

	if (uniqueID != nullptr)
	{
		if (*uniqueID == RPC_ClientCheck) {
			unsigned char type;
			parameters->ReadBits(&type, 8, 1);
			parameters->ResetReadPointer();
			if (type == 0x5) {
				#pragma pack(push, 1)
				struct CCheck {
					unsigned char type;
					unsigned int address;
					unsigned char result;
				};
				#pragma pack(pop)
				CCheck* data = reinterpret_cast<CCheck*>(parameters->GetData());
				if (data->result != lastResult) {
					if (AddrMap.find(data->address) == AddrMap.end()) {
						AddrMap[data->address] = data->result;
						char buf[100];
						sprintf_s(buf, "Address: 0x%X | Result : 0x%X", data->address, data->result);
						DWORD sampBase = reinterpret_cast<DWORD>(GetModuleHandle(L"samp.dll"));
						((void(__thiscall*)(void*, unsigned int, const char*))(sampBase + 0x679F0))(*reinterpret_cast<void**>(sampBase + 0x26E8C8), 0xff0000, buf);
					}
				}
			}
		}
	}
	return pRakClient->RPC(uniqueID, parameters, priority, reliability, orderingChannel, shiftTimestamp);
}

bool HookedRakClientInterface::Send(BitStream * bitStream, PacketPriority priority, PacketReliability reliability, char orderingChannel)
{
	return pRakClient->Send(bitStream, priority, reliability, orderingChannel);
}

Packet *HookedRakClientInterface::Receive(void)
{
	Packet *packet = pRakClient->Receive();
	if (packet != nullptr && packet->data && packet->length > 0)
	{

	}
	return packet;
}

bool HookedRakClientInterface::Connect(const char* host, unsigned short serverPort, unsigned short clientPort, unsigned int depreciated, int threadSleepTimer)
{
	return pRakClient->Connect(host, serverPort, clientPort, depreciated, threadSleepTimer);
}

void HookedRakClientInterface::Disconnect(unsigned int blockDuration, unsigned char orderingChannel)
{
	pRakClient->Disconnect(blockDuration, orderingChannel);
}

void HookedRakClientInterface::InitializeSecurity(const char *privKeyP, const char *privKeyQ)
{
	pRakClient->InitializeSecurity(privKeyP, privKeyQ);
}

void HookedRakClientInterface::SetPassword(const char *_password)
{
	pRakClient->SetPassword(_password);
}

bool HookedRakClientInterface::HasPassword(void) const
{
	return pRakClient->HasPassword();
}

bool HookedRakClientInterface::Send(const char *data, const int length, PacketPriority priority, PacketReliability reliability, char orderingChannel)
{
	return pRakClient->Send(data, length, priority, reliability, orderingChannel);
}

void HookedRakClientInterface::DeallocatePacket(Packet *packet)
{
	pRakClient->DeallocatePacket(packet);
}

void HookedRakClientInterface::PingServer(void)
{
	pRakClient->PingServer();
}

void HookedRakClientInterface::PingServer(const char* host, unsigned short serverPort, unsigned short clientPort, bool onlyReplyOnAcceptingConnections)
{
	pRakClient->PingServer(host, serverPort, clientPort, onlyReplyOnAcceptingConnections);
}

int HookedRakClientInterface::GetAveragePing(void)
{
	return pRakClient->GetAveragePing();
}

int HookedRakClientInterface::GetLastPing(void) const
{
	return pRakClient->GetLastPing();
}

int HookedRakClientInterface::GetLowestPing(void) const
{
	return pRakClient->GetLowestPing();
}

int HookedRakClientInterface::GetPlayerPing(const PlayerID playerId)
{
	return pRakClient->GetPlayerPing(playerId);
}

void HookedRakClientInterface::StartOccasionalPing(void)
{
	pRakClient->StartOccasionalPing();
}

void HookedRakClientInterface::StopOccasionalPing(void)
{
	pRakClient->StopOccasionalPing();
}

bool HookedRakClientInterface::IsConnected(void) const
{
	return pRakClient->IsConnected();
}

unsigned int HookedRakClientInterface::GetSynchronizedRandomInteger(void) const
{
	return pRakClient->GetSynchronizedRandomInteger();
}

bool HookedRakClientInterface::GenerateCompressionLayer(unsigned int inputFrequencyTable[256], bool inputLayer)
{
	return pRakClient->GenerateCompressionLayer(inputFrequencyTable, inputLayer);
}

bool HookedRakClientInterface::DeleteCompressionLayer(bool inputLayer)
{
	return pRakClient->DeleteCompressionLayer(inputLayer);
}

void HookedRakClientInterface::RegisterAsRemoteProcedureCall(int* uniqueID, void(*functionPointer) (RPCParameters *rpcParms))
{
	pRakClient->RegisterAsRemoteProcedureCall(uniqueID, functionPointer);
}

void HookedRakClientInterface::RegisterClassMemberRPC(int* uniqueID, void *functionPointer)
{
	pRakClient->RegisterClassMemberRPC(uniqueID, functionPointer);
}

void HookedRakClientInterface::UnregisterAsRemoteProcedureCall(int* uniqueID)
{
	pRakClient->UnregisterAsRemoteProcedureCall(uniqueID);
}

bool HookedRakClientInterface::RPC(int* uniqueID, const char *data, unsigned int bitLength, PacketPriority priority, PacketReliability reliability, char orderingChannel, bool shiftTimestamp)
{
	return pRakClient->RPC(uniqueID, data, bitLength, priority, reliability, orderingChannel, shiftTimestamp);
}

void HookedRakClientInterface::SetTrackFrequencyTable(bool b)
{
	pRakClient->SetTrackFrequencyTable(b);
}

bool HookedRakClientInterface::GetSendFrequencyTable(unsigned int outputFrequencyTable[256])
{
	return pRakClient->GetSendFrequencyTable(outputFrequencyTable);
}

float HookedRakClientInterface::GetCompressionRatio(void) const
{
	return pRakClient->GetCompressionRatio();
}

float HookedRakClientInterface::GetDecompressionRatio(void) const
{
	return pRakClient->GetDecompressionRatio();
}

void HookedRakClientInterface::AttachPlugin(void *messageHandler)
{
	pRakClient->AttachPlugin(messageHandler);
}

void HookedRakClientInterface::DetachPlugin(void *messageHandler)
{
	pRakClient->DetachPlugin(messageHandler);
}

BitStream * HookedRakClientInterface::GetStaticServerData(void)
{
	return pRakClient->GetStaticServerData();
}

void HookedRakClientInterface::SetStaticServerData(const char *data, const int length)
{
	pRakClient->SetStaticServerData(data, length);
}

BitStream * HookedRakClientInterface::GetStaticClientData(const PlayerID playerId)
{
	return pRakClient->GetStaticClientData(playerId);
}

void HookedRakClientInterface::SetStaticClientData(const PlayerID playerId, const char *data, const int length)
{
	pRakClient->SetStaticClientData(playerId, data, length);
}

void HookedRakClientInterface::SendStaticClientDataToServer(void)
{
	pRakClient->SendStaticClientDataToServer();
}

PlayerID HookedRakClientInterface::GetServerID(void) const
{
	return pRakClient->GetServerID();
}

PlayerID HookedRakClientInterface::GetPlayerID(void) const
{
	return pRakClient->GetPlayerID();
}

PlayerID HookedRakClientInterface::GetInternalID(void) const
{
	return pRakClient->GetInternalID();
}

const char* HookedRakClientInterface::PlayerIDToDottedIP(const PlayerID playerId) const
{
	return pRakClient->PlayerIDToDottedIP(playerId);
}

void HookedRakClientInterface::PushBackPacket(Packet *packet, bool pushAtHead)
{
	pRakClient->PushBackPacket(packet, pushAtHead);
}

void HookedRakClientInterface::SetRouterInterface(void *routerInterface)
{
	pRakClient->SetRouterInterface(routerInterface);
}

void HookedRakClientInterface::RemoveRouterInterface(void *routerInterface)
{
	pRakClient->RemoveRouterInterface(routerInterface);
}

void HookedRakClientInterface::SetTimeoutTime(RakNetTime timeMS)
{
	pRakClient->SetTimeoutTime(timeMS);
}

bool HookedRakClientInterface::SetMTUSize(int size)
{
	return pRakClient->SetMTUSize(size);
}

int HookedRakClientInterface::GetMTUSize(void) const
{
	return pRakClient->GetMTUSize();
}

void HookedRakClientInterface::AllowConnectionResponseIPMigration(bool allow)
{
	pRakClient->AllowConnectionResponseIPMigration(allow);
}

void HookedRakClientInterface::AdvertiseSystem(const char *host, unsigned short remotePort, const char *data, int dataLength)
{
	pRakClient->AdvertiseSystem(host, remotePort, data, dataLength);
}

RakNetStatisticsStruct* const HookedRakClientInterface::GetStatistics(void)
{
	return pRakClient->GetStatistics();
}

void HookedRakClientInterface::ApplyNetworkSimulator(double maxSendBPS, unsigned short minExtraPing, unsigned short extraPingVariance)
{
	pRakClient->ApplyNetworkSimulator(maxSendBPS, minExtraPing, extraPingVariance);
}

bool HookedRakClientInterface::IsNetworkSimulatorActive(void)
{
	return pRakClient->IsNetworkSimulatorActive();
}

PlayerIndex HookedRakClientInterface::GetPlayerIndex(void)
{
	return pRakClient->GetPlayerIndex();
}

bool HookedRakClientInterface::RPC_(int* uniqueID, BitStream *bitStream, PacketPriority priority, PacketReliability reliability, char orderingChannel, bool shiftTimestamp, NetworkID networkID)
{
	return pRakClient->RPC_(uniqueID, bitStream, priority, reliability, orderingChannel, shiftTimestamp, networkID);
}