#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <entity2/entityinstance.h>

CEntityInstance * entityinstance();

int main() {

    entityinstance()->Connect();

    return 0;
}
