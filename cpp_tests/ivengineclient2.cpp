#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <cdll_int.h>

// Overriding an existing slot forces a complete dump even when the SDK's
// derived class declares no virtual methods of its own. No slots are added.
// The engine's concrete table is CEngineClient, which the SDK does not declare,
// so this probe stands in for it through the alias_symbols mapping.
class IVEngineClient2VTableProbe : public IVEngineClient2
{
public:
    bool IsPaused() override = 0;
};

IVEngineClient2VTableProbe * ivengineclient2();

int main() {

    ivengineclient2()->IsPaused();

    return 0;
}
