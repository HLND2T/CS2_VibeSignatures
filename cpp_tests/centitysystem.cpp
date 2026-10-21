#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

// The SDK serializer references this opaque game-side type.
class CPlayerBitVec;

#include <entity2/entitysystem.h>

CEntitySystem * entitysystem();

int main() {

    entitysystem()->ClearEntityDatabase(CED_NORMAL);

    return 0;
}
