// Minimal protobuf base for network game server vtable tests.
// These tests do not validate GameSessionConfiguration_t's record layout.
#ifndef NETWORKBASETYPES_PB_H_STUB
#define NETWORKBASETYPES_PB_H_STUB

class CSVCMsg_GameSessionConfiguration
{
public:
    virtual ~CSVCMsg_GameSessionConfiguration() = default;
};

// Held by value in CServerSideClientBase, so the type has to be complete.
// Its payload does not affect the vtable layout these tests compare.
class CMsgPlayerInfo
{
public:
    virtual ~CMsgPlayerInfo() = default;

private:
    void *m_pOpaque[ 6 ];
};

// Defined in networkbasetypes.proto; CServerSideClientBase stores it by value.
enum SignonState_t : int
{
    SIGNONSTATE_NONE = 0,
    SIGNONSTATE_CHALLENGE = 1,
    SIGNONSTATE_CONNECTED = 2,
    SIGNONSTATE_NEW = 3,
    SIGNONSTATE_PRESPAWN = 4,
    SIGNONSTATE_SPAWN = 5,
    SIGNONSTATE_FULL = 6,
    SIGNONSTATE_CHANGELEVEL = 7,
};

#endif // NETWORKBASETYPES_PB_H_STUB
