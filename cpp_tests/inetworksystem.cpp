#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

// The SDK serializer references this opaque game-side type.
class CPlayerBitVec;

#include <networksystem/inetworksystem.h>

INetworkSystem * networksystem();

int main() {

    networksystem()->InitGameServer();

    return 0;
}
