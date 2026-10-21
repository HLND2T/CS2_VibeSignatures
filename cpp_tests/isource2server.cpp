#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <engine2/isource2server.h>

ISource2Server *sourceserver();

int main()
{
	sourceserver()->PreWorldUpdate(false);

	return 0;
}
