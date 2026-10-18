#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <icvar.h>

ICvar * icvar();

int main() {

    icvar()->StripDevelopmentFlags();

    return 0;
}
