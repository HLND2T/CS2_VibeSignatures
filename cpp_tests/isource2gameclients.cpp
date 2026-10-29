#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <engine2/isource2server.h>

ISource2GameClients *sourcegameclients();

int main()
{
	sourcegameclients()->ClientFullyConnect(CPlayerSlot(0));

	return 0;
}
