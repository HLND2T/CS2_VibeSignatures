#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <tier0/icvar.h>

ICvar * icvar();

int main() {

    icvar()->StripDevelopmentFlags();

    return 0;
}
