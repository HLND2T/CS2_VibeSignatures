#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <tier1/convar.h>
#include <iloopmode.h>

ILoopMode * loopmode();

int main() {

    loopmode()->LoopShutdown();

    return 0;
}
