#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

// These dependencies are unused by the client declarations under test.
#define IENGINESERVICE_H
#define INETWORKCLIENTSERVICE_H
#define NS_ADDRESS_H

#include <iclient.h>

// Overriding an existing slot forces a complete dump even when the SDK's
// derived class declares no virtual methods of its own. No slots are added.
class CNetworkGameClientVTableProbe : public CNetworkGameClient
{
public:
    void TransmitNetChannel() override = 0;
};

CNetworkGameClientBase * networkgameclientbase();
CNetworkGameClientVTableProbe * networkgameclient();

int main() {

    networkgameclientbase()->TransmitNetChannel();
    networkgameclient()->TransmitNetChannel();

    return 0;
}
