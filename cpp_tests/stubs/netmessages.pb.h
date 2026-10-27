// Stub for the generated netmessages.pb.h.
// CServerSideClientBase references these message types in its virtual
// signatures, so they must be declared for the vtable tests to compile.
// The protobuf payload itself is unused by vtable layout comparison.
#ifndef NETMESSAGES_PB_H_STUB
#define NETMESSAGES_PB_H_STUB

#include <networkbasetypes.pb.h>

#define NETMESSAGES_PB_STUB_MESSAGE( name ) \
	class name                              \
	{                                       \
	public:                                 \
		virtual ~name() = default;          \
	}

NETMESSAGES_PB_STUB_MESSAGE( CNETMsg_Tick );
NETMESSAGES_PB_STUB_MESSAGE( CNETMsg_StringCmd );
NETMESSAGES_PB_STUB_MESSAGE( CNETMsg_SetConVar );
NETMESSAGES_PB_STUB_MESSAGE( CNETMsg_SignonState );
NETMESSAGES_PB_STUB_MESSAGE( CNETMsg_SpawnGroup_LoadCompleted );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_ClientInfo );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_BaselineAck );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_LoadingProgress );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_SplitPlayerConnect );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_SplitPlayerDisconnect );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_CmdKeyValues );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_RconServerDetails );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_Diagnostic );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_Move );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_VoiceData );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_RespondCvarValue );
NETMESSAGES_PB_STUB_MESSAGE( NetMessagePacketStart );
NETMESSAGES_PB_STUB_MESSAGE( NetMessagePacketEnd );
NETMESSAGES_PB_STUB_MESSAGE( NetMessageConnectionClosed );
NETMESSAGES_PB_STUB_MESSAGE( NetMessageConnectionCrashed );
NETMESSAGES_PB_STUB_MESSAGE( NetMessageSplitscreenUserChanged );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_HltvReplay );
NETMESSAGES_PB_STUB_MESSAGE( CCLCMsg_HltvFixupOperatorTick );
NETMESSAGES_PB_STUB_MESSAGE( CSVCMsg_UserMessage );
NETMESSAGES_PB_STUB_MESSAGE( CSVCMsg_PacketEntities );

#undef NETMESSAGES_PB_STUB_MESSAGE

#endif // NETMESSAGES_PB_H_STUB
