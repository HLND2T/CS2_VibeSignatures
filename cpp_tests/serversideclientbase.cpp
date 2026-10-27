#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <engine2/serversideclientbase.h>

// Overriding an existing slot forces a complete dump even when the SDK's
// derived class declares no virtual methods of its own. No slots are added.
class CServerSideClientBaseVTableProbe : public CServerSideClientBase
{
public:
    void Reconnect() override = 0;
};

CServerSideClientBaseVTableProbe * serversideclientbase();

int main() {

    serversideclientbase()->Reconnect();

    return 0;
}
