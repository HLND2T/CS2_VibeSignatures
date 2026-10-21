#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <engine2/iengineservicemgr.h>

ILoopType * looptype();

int main() {

    looptype()->AddEngineService("test");

    return 0;
}
