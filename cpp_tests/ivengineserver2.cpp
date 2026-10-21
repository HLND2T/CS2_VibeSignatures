#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

// The engine interface references this opaque game-side type.
class CPlayerBitVec;

#include <engine2/ivengineserver2.h>

IVEngineServer2 *engineserver();

int main()
{
	engineserver()->GetSteamUniverse();

	return 0;
}
