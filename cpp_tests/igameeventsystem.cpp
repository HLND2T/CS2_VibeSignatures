#include <tier0/platform.h>
#undef RESTRICT
#define RESTRICT

#include <appframework/IAppSystem.h>
#include <tier1/convar.h>

// Avoid the eiface.h / inetchannel.h protobuf include chains.
#define EIFACE_H
#define INETCHANNEL_H
enum NetChannelBufType_t : int8 {};

#include <engine/igameeventsystem.h>

IGameEventSystem * gameeventsystem();

int main() {

    gameeventsystem()->ProcessQueuedEvents();

    return 0;
}
