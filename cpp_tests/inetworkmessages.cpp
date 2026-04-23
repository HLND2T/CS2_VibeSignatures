#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

// Pre-define include guards to avoid heavy transitive includes
// eiface.h -> edict.h -> cmodel.h -> gametrace.h -> variant.h -> vector.h (missing)
// inetchannel.h -> eiface.h (same chain) and needs protobuf-generated ENetworkDisconnectionReason
#define EIFACE_H
#define INETCHANNEL_H
enum NetChannelBufType_t : int8 {};

// Forward declarations for types added to inetworkserializer.h in hl2sdk_cs2 update
class CPlayerBitVec;
typedef void *(*SchemaClassManipulatorFn_t)(int, void *);
typedef void *(*SchemaCollectionManipulatorFn_t)(int, void *, int, int);

#include <networksystem/inetworkmessages.h>

INetworkMessages * networkmessages();

int main() {

    networkmessages()->GetLoggingChannel();

    return 0;
}
