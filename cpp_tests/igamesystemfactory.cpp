#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <igamesystemfactory.h>

IGameSystemFactory * instanceptr();

int main() {

    instanceptr()->Shutdown();

    return 0;
}
