#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

// Pre-define include guards to avoid heavy transitive includes (eiface.h -> protobuf)
#define INETCHANNEL_H
#define BITBUF_H
class INetChannel;
enum ENetworkDisconnectionReason {};
struct netadr_t { int type; unsigned short port; unsigned int ip; };
class CSteamID {};

#include <networksystem/inetworksystem.h>

INetworkSystem * networksystem();

int main() {

    networksystem()->InitGameServer();

    return 0;
}
