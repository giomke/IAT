#include "Hook.h"


BOOL APIENTRY DllMain
(
	HINSTANCE hinsDLL,
	DWORD fdwReason,
	LPVOID lpReserved

)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hinsDLL);
		if (!parse())
			FreeLibrary(hinsDLL);
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}