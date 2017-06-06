#include <windows.h>
#include "ClassSecInfoTS.h"

#define _SafeCOMRelease(x) { if (NULL != x) { x->Release(); x = NULL; } }

HANDLE g_hHeap;

int
CALLBACK
WinMain (
   _In_ HINSTANCE hInstance,
   _In_opt_ HINSTANCE hPrevInstance,
   _In_ LPSTR lpCmdLine,
   _In_ int nShowCmd
)
{
   BOOL bResult;
   HRESULT hResult;

   CSecInfoTS *pSecInfo = NULL;

   hResult = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
   if (FAILED(hResult))
      return EXIT_FAILURE;

   g_hHeap = HeapCreate(
      0,          // flOptions
      0,          // dwInitialSize
      0           // dwMaximumSize
   );

   if (g_hHeap == NULL)
      return EXIT_FAILURE;

   pSecInfo = new CSecInfoTS(TEXT("RDP-Tcp"));
   if (pSecInfo != NULL)
   {
      bResult = EditSecurity(NULL, pSecInfo);
      _SafeCOMRelease(pSecInfo);
   }

   HeapDestroy(g_hHeap);
   CoUninitialize();

   return EXIT_SUCCESS;
}