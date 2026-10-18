#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <networkstringtabledefs.h>

INetworkStringTableContainer * stringtablecontainer();

int main() {

    stringtablecontainer()->RemoveAllTables();

    return 0;
}
