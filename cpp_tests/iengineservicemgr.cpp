#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <engine2/iengineservicemgr.h>

IEngineServiceMgr * engineservicemgr();

int main() {

    engineservicemgr()->PrintStatus();

    return 0;
}
