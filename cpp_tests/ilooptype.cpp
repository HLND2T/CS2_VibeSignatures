#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <tier1/convar.h>
#include <iloopmode.h>

ILoopType * looptype();

int main() {

    looptype()->AddEngineService("test");

    return 0;
}
