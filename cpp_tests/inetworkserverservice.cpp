#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <engine2/inetworkserverservice.h>

INetworkServerService * networkserverservice();

int main() {

    networkserverservice()->IsServerRunning();
    networkserverservice()->IsActiveInGame();
    networkserverservice()->GetServerSerializersCRC();

    return 0;
}
