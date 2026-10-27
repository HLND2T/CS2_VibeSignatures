#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <engine2/serversideclient.h>

// Overriding an existing slot forces a complete dump even when the SDK's
// derived class declares no virtual methods of its own. No slots are added.
class CServerSideClientVTableProbe : public CServerSideClient
{
public:
    void Reconnect() override = 0;
};

CServerSideClientVTableProbe * serversideclient();

int main() {

    serversideclient()->Reconnect();

    return 0;
}
