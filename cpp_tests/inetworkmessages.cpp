#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

// The SDK serializer references this opaque game-side type.
class CPlayerBitVec;

#include <networksystem/inetworkmessages.h>

INetworkMessages * networkmessages();

int main() {

    networkmessages()->GetLoggingChannel();

    return 0;
}
