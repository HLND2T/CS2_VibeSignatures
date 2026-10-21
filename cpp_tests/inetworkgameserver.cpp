#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

// The SDK serializer references this opaque game-side type.
class CPlayerBitVec;

#include <engine2/inetworkgameserver.h>
#include <engine2/networkgameserverbase.h>

INetworkGameServer * networkgameserver();
CNetworkGameServerBase * networkgameserverbase();

int main() {

    networkgameserver()->GetMaxClients();
    networkgameserverbase()->SetMaxClients(64);

    return 0;
}
