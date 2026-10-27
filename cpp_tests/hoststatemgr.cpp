#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <engine2/hoststate.h>

// Overriding existing slots forces a complete dump even when the SDK's
// derived class declares no virtual methods of its own. No slots are added.
// The secondary-base override mirrors CHostStateMgr, which implements
// ISwitchLoopModeStatusNotify; Itanium appends it to the primary table while
// MSVC keeps it in the secondary vftable.
class CHostStateMgrVTableProbe : public CHostStateMgr
{
public:
	void RequestHS_Quit() override = 0;
	void OnSwitchLoopModeFinished( const char *, uint32, bool ) override = 0;
};

CHostStateMgrVTableProbe * hoststatemgr();

int main() {

	hoststatemgr()->RequestHS_Quit();

	return 0;
}
