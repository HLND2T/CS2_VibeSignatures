#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

// The SDK serializer references this opaque game-side type.
class CPlayerBitVec;

#include <engine2/igameeventsystem.h>

IGameEventSystem * gameeventsystem();

int main() {

    gameeventsystem()->ProcessQueuedEvents();

    return 0;
}
