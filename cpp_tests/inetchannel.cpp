#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <networksystem/inetchannel.h>

INetChannel * netchannel();

int main() {

    netchannel()->Reset();

    return 0;
}
