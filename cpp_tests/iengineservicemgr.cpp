#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <tier1/convar.h>
#include <KeyValues.h>

// RenderDeviceInfo_t is defined via eiface.h (heavy protobuf chain); forward-declare
// the opaque type since IEngineServiceMgr only references it by reference.
struct RenderDeviceInfo_t;

#include <engine/IEngineService.h>

IEngineServiceMgr * engineservicemgr();

int main() {

    engineservicemgr()->PrintStatus();

    return 0;
}
