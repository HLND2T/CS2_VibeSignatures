#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <tier0/icommandline.h>

ICommandLine * cmdline();

int main() {

    cmdline()->ParmCount();

    return 0;
}
