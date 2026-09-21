#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT
#undef CreateEvent  // WinAPI macro renames IGameEventManager2::CreateEvent -> CreateEventA

#include <igameevents.h>

IGameEventManager2 * gameeventmanager();

int main() {

    gameeventmanager()->Reset();

    return 0;
}
