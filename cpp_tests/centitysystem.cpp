#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

// Pre-define include guards to avoid heavy transitive includes
// eiface.h -> edict.h -> cmodel.h -> gametrace.h -> variant.h -> vector.h (missing)
//          -> network_connection.pb.h (protobuf, not available)
// inetworkserializer.h -> iprotobufbinding.h -> inetchannel.h (pulls in ENetworkDisconnectionReason etc.)
#define EIFACE_H
#define INETCHANNEL_H

// Forward declarations for types referenced from inetworkserializer.h chain
class CPlayerBitVec;
class INetChannel;
enum ENetworkDisconnectionReason {};
enum NetChannelBufType_t : int8 {};

// inetworkserializer.h references SchemaClassManipulatorFn_t / SchemaCollectionManipulatorFn_t
// but the canonical typedefs live in schemasystem/schematypes.h, which is pulled in later
// via vscript/ivscript.h -> variant.h -> entity2/entityidentity.h. Include it up front so
// inetworkserializer.h sees the real typedefs (avoids redefinition with different argument types).
#include <schemasystem/schematypes.h>

#include <entity2/entitysystem.h>

CEntitySystem * entitysystem();

int main() {

    entitysystem()->ClearEntityDatabase(CED_NORMAL);

    return 0;
}
