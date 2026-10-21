#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <engine2/iengineservicemgr.h>

ILoopMode * loopmode();

int main() {

    loopmode()->LoopShutdown();

    return 0;
}
