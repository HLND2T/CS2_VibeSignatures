#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

// Pre-define include guards to avoid heavy transitive include chains.
#define EDICT_H
#define EIFACE_H
#define INETCHANNEL_H

class CGlobalVars;
class IRecipientFilter;
class ServerClass;
struct RenderDeviceInfo_t;
typedef uint32 SpawnGroupHandle_t;

class CPlayerUserId
{
public:
    CPlayerUserId(int index) : m_Index(static_cast<unsigned short>(index)) {}

    int Get() const { return m_Index; }

private:
    unsigned short m_Index;
};

class bf_read;
enum NetChannelBufType_t : int8 {};

// Forward declaration used by inetworkserializer.h.
class CPlayerBitVec;

#include <bitvec.h>
#include <playerslot.h>
#include <tier1/convar.h>
#include <iserver.h>

INetworkServerService * networkserverservice();

int main() {

    networkserverservice()->IsServerRunning();
    networkserverservice()->IsActiveInGame();
    networkserverservice()->GetServerSerializersCRC();

    return 0;
}
