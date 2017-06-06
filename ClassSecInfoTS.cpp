#include <windows.h>
#include <wtsapi32.h>
#include <sddl.h>
#include <tchar.h>
#include "ClassSecInfoTS.h"
#include "TSAccessRight.h"

extern HANDLE g_hHeap;

#define _SafeHeapRelease(x) { if (NULL != x) { HeapFree(g_hHeap, 0, x); x = NULL; } }
#define TEXT_SIZE       512

CSecInfoTS::CSecInfoTS (
   _In_z_ LPWSTR szListenerName
)
{
   BOOL bResult;

   PSECURITY_DESCRIPTOR pSd;
   DWORD dwSize;

   //
   // Initialize Class variables.
   //
   this->m_cRef = 1;
   this->m_szListenerName = NULL;

   // Relative SD
   this->pRelativeSD = NULL;
   this->dwRelativeSDSize = 0;

   // Absolute SD (SD + Owner, Group, DACL, SACL)
   this->pAbsoluteSD = NULL;
   this->pOwner = NULL;
   this->pPrimaryGroup = NULL;
   this->pDacl = NULL;
   this->pSacl = NULL;

   //
   // Get TS Security Descriptor (Only DACL and SACL).
   //
#pragma warning(suppress: 6387)
   WTSGetListenerSecurity(
      WTS_CURRENT_SERVER_HANDLE,
      NULL,
      0,
      szListenerName,
      DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
      NULL,
      0,
      &dwSize
   );

   if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
   {
      MessageBox(NULL, TEXT("Unable to get SD."), TEXT("Error"), MB_OK | MB_ICONERROR);
      return;
   }

   pSd = (PSECURITY_DESCRIPTOR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwSize);

   bResult = WTSGetListenerSecurity(
      WTS_CURRENT_SERVER_HANDLE,
      NULL,
      0,
      szListenerName,
      DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
      pSd,
      dwSize,
      &dwSize
   );

   if (bResult == FALSE)
   {
      MessageBox(NULL, TEXT("Unable to get SD."), TEXT("Error"), MB_OK | MB_ICONERROR);
      _SafeHeapRelease(pSd);
      return;
   }

   //
   // Everything is OK. Set variables.
   //
   pRelativeSD = pSd;
   dwRelativeSDSize = dwSize;
   UpdateAbsoluteSd();

   dwSize = wcslen(szListenerName) + 1;      // +1 for NULL character
   this->m_szListenerName = (LPWSTR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwSize*sizeof(WCHAR));
   if (this->m_szListenerName)
      wcscpy_s(this->m_szListenerName, dwSize, szListenerName);

   return;
}

CSecInfoTS::~CSecInfoTS (
)
{
   _SafeHeapRelease(m_szListenerName);
   _SafeHeapRelease(pRelativeSD);
   _SafeHeapRelease(pAbsoluteSD);
   _SafeHeapRelease(pOwner);
   _SafeHeapRelease(pPrimaryGroup);
   _SafeHeapRelease(pDacl);
   _SafeHeapRelease(pSacl);
}

//
// IUnknown methods
//

STDMETHODIMP_(ULONG)
CSecInfoTS::AddRef()
{
   m_cRef++;
   return m_cRef;
}

STDMETHODIMP_(ULONG)
CSecInfoTS::Release (
)
{
   m_cRef--;

   if (m_cRef == 0)
   {
      delete this;
   }

   return m_cRef;
}

STDMETHODIMP
CSecInfoTS::QueryInterface (
   REFIID riid,
   VOID **ppvObject
)
{
   if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_ISecurityInformation))
   {
      *ppvObject = (LPSECURITYINFO)this;
      m_cRef++;
      return S_OK;
   }
   else
   {
      *ppvObject = NULL;
      return E_NOINTERFACE;
   }
}

//
// ISecurityInformation methods
//

STDMETHODIMP
CSecInfoTS::GetObjectInformation (
   PSI_OBJECT_INFO pObjectInfo
)
{
   pObjectInfo->pszObjectName = this->m_szListenerName;
   pObjectInfo->pszPageTitle = NULL;
   pObjectInfo->pszServerName = NULL;
   pObjectInfo->hInstance = NULL;
   pObjectInfo->dwFlags = SI_EDIT_PERMS | SI_EDIT_AUDITS | SI_ADVANCED | SI_NO_TREE_APPLY | SI_NO_ACL_PROTECT | SI_ENABLE_EDIT_ATTRIBUTE_CONDITION;
   return(S_OK);
}

STDMETHODIMP
CSecInfoTS::GetSecurity (
   SECURITY_INFORMATION RequestedInformation,
   PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
   BOOL fDefault
)
{
   if ((dwRelativeSDSize == 0) || (this->pRelativeSD == NULL))
   {
      MessageBox(NULL, TEXT("Class SD is NULL"), TEXT("Error"), MB_OK | MB_ICONERROR);
   }
   else
   {
      *ppSecurityDescriptor = LocalAlloc(0, dwRelativeSDSize);
      memcpy(*ppSecurityDescriptor, this->pRelativeSD, dwRelativeSDSize);
   }

   return(S_OK);
}

STDMETHODIMP
CSecInfoTS::SetSecurity (
   SECURITY_INFORMATION SecurityInformation,
   PSECURITY_DESCRIPTOR pSecurityDescriptor
)
{
   BOOL bResult;
   DWORD dwSize;

   TCHAR szMessage[TEXT_SIZE];

   SECURITY_DESCRIPTOR NewAbsoluteSd = { 0 };
   PSECURITY_DESCRIPTOR pNewRelaviveSd = NULL;

   BOOL bAclPresent;
   BOOL bAclDefault;
   PACL pAcl;

   memcpy(&NewAbsoluteSd, this->pAbsoluteSD, sizeof(NewAbsoluteSd));

   //
   // Update Security Descriptor.
   //
   if (SecurityInformation & DACL_SECURITY_INFORMATION)
   {
      bResult = GetSecurityDescriptorDacl(pSecurityDescriptor, &bAclPresent, &pAcl, &bAclDefault);
      if (bResult == FALSE)
      {
         _stprintf_s(szMessage, TEXT_SIZE, TEXT("GetSecurityDescriptorDacl() failed.\r\nError code is %u."), GetLastError());
         MessageBox(NULL, szMessage, TEXT("Error"), MB_OK | MB_ICONERROR);
         return(S_FALSE);
      }

      bResult = SetSecurityDescriptorDacl(&NewAbsoluteSd, bAclPresent, pAcl, bAclDefault);
      if (bResult == FALSE)
      {
         _stprintf_s(szMessage, TEXT_SIZE, TEXT("SetSecurityDescriptorDacl() failed.\r\nError code is %u."), GetLastError());
         MessageBox(NULL, szMessage, TEXT("Error"), MB_OK | MB_ICONERROR);
         return(S_FALSE);
      }

      //DisplaySDDL(pSecurityDescriptor);
   }

   if (SecurityInformation & SACL_SECURITY_INFORMATION)
   {
      bResult = GetSecurityDescriptorSacl(pSecurityDescriptor, &bAclPresent, &pAcl, &bAclDefault);
      if (bResult == FALSE)
      {
         _stprintf_s(szMessage, TEXT_SIZE, TEXT("GetSecurityDescriptorSacl() failed.\r\nError code is %u."), GetLastError());
         return(S_FALSE);
      }

      bResult = SetSecurityDescriptorSacl(&NewAbsoluteSd, bAclPresent, pAcl, bAclDefault);
      if (bResult == FALSE)
      {
         _stprintf_s(szMessage, TEXT_SIZE, TEXT("SetSecurityDescriptorSacl() failed.\r\nError code is %u."), GetLastError());
         MessageBox(NULL, szMessage, TEXT("Error"), MB_OK | MB_ICONERROR);
         return(S_FALSE);
      }
   }

   //
   // Create new Security Descriptor.
   //
   dwSize = 0;
   MakeSelfRelativeSD(&NewAbsoluteSd, NULL, &dwSize);
   if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
   {
      _stprintf_s(szMessage, TEXT_SIZE, TEXT("Unable to convert Security Descriptor.\r\nError code is %u."), GetLastError());
      MessageBox(NULL, szMessage, TEXT("Error"), MB_OK | MB_ICONERROR);

      return(S_FALSE);
   }

   pNewRelaviveSd = (PSECURITY_DESCRIPTOR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwSize);

   bResult = MakeSelfRelativeSD(&NewAbsoluteSd, pNewRelaviveSd, &dwSize);
   if (bResult == FALSE)
   {
      _stprintf_s(szMessage, TEXT_SIZE, TEXT("Unable to convert Security Descriptor.\r\nError code is %u."), GetLastError());
      MessageBox(NULL, szMessage, TEXT("Error"), MB_OK | MB_ICONERROR);

      _SafeHeapRelease(pNewRelaviveSd);
      return(S_FALSE);
   }

   //
   // Set Terminal Service Security Descriptor.
   //
#pragma warning(suppress: 6387)
   bResult = WTSSetListenerSecurity(
      WTS_CURRENT_SERVER_HANDLE,
      NULL,
      0,
      this->m_szListenerName,
      DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
      pNewRelaviveSd
   );

   if (bResult == FALSE)
   {
      _SafeHeapRelease(pNewRelaviveSd);

      _stprintf_s(szMessage, TEXT_SIZE, TEXT("Unable to set new Security Descriptor.\r\nError code is %u."), GetLastError());
      MessageBox(NULL, szMessage, TEXT("Error"), MB_OK | MB_ICONERROR);
      return (S_FALSE);
   }
   else
   {
      //
      // Set SD OK. Free old class Security Descriptor and update new one (addr + size).
      //
      _SafeHeapRelease(this->pRelativeSD);
      this->pRelativeSD = pNewRelaviveSd;
      this->dwRelativeSDSize = dwSize;
      UpdateAbsoluteSd();
   }

   return(S_OK);
}

STDMETHODIMP
CSecInfoTS::PropertySheetPageCallback (
   HWND hwnd,
   UINT uMsg,
   SI_PAGE_TYPE uPage
)
{
   return S_OK;
}

STDMETHODIMP
CSecInfoTS::GetAccessRights (
   const GUID* pguidObjectType,
   DWORD dwFlags,
   PSI_ACCESS *ppAccess,
   ULONG *pcAccesses,
   ULONG *piDefaultAccess
)
{
   *ppAccess = TSSIAccess;
   *pcAccesses = sizeof(TSSIAccess) / sizeof(SI_ACCESS);
   *piDefaultAccess = 0;

   return(S_OK);
}

STDMETHODIMP
CSecInfoTS::MapGeneric (
   const GUID *pguidObjectType,
   UCHAR *pAceFlags,
   ACCESS_MASK *pMask
)
{
   return(S_OK);
}

STDMETHODIMP
CSecInfoTS::GetInheritTypes (
   PSI_INHERIT_TYPE *ppInheritTypes,
   ULONG *pcInheritTypes
)
{
   return(S_OK);
}

//
// ISecurityInformation4 methods
//

STDMETHODIMP
CSecInfoTS::GetSecondarySecurity (
   PSECURITY_OBJECT *pSecurityObjects,
   PULONG pSecurityObjectCount
)
{
   MessageBox(NULL, TEXT("GetSecondarySecurity() called."), TEXT("Info"), MB_OK);
   return(S_OK);
}

//
// Private methods
//

BOOL
CSecInfoTS::UpdateAbsoluteSd (
)
{
   BOOL bResult;

   DWORD dwAbsoluteSDSize = 0;
   DWORD dwOwnerSize = 0;
   DWORD dwPrimaryGroupSize = 0;
   DWORD dwDaclSize = 0;
   DWORD dwSaclSize = 0;

   MakeAbsoluteSD(
      this->pRelativeSD,
      NULL,
      &dwAbsoluteSDSize,
      NULL,
      &dwDaclSize,
      NULL,
      &dwSaclSize,
      NULL,
      &dwOwnerSize,
      NULL,
      &dwPrimaryGroupSize
   );

   if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
   {
      return FALSE;
   }

   _SafeHeapRelease(pAbsoluteSD);
   _SafeHeapRelease(pOwner);
   _SafeHeapRelease(pPrimaryGroup);
   _SafeHeapRelease(pDacl);
   _SafeHeapRelease(pSacl);

   pAbsoluteSD = (PSECURITY_DESCRIPTOR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwAbsoluteSDSize);
   pDacl = (PACL)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwDaclSize);
   pSacl = (PACL)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwSaclSize);
   pOwner = (PSID)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwOwnerSize);
   pPrimaryGroup = (PSID)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwPrimaryGroupSize);

   bResult = MakeAbsoluteSD(
      this->pRelativeSD,
      pAbsoluteSD,
      &dwAbsoluteSDSize,
      pDacl,
      &dwDaclSize,
      pSacl,
      &dwSaclSize,
      pOwner,
      &dwOwnerSize,
      pPrimaryGroup,
      &dwPrimaryGroupSize
   );

   if (bResult == FALSE)
   {
      _SafeHeapRelease(pAbsoluteSD);
      _SafeHeapRelease(pOwner);
      _SafeHeapRelease(pPrimaryGroup);
      _SafeHeapRelease(pDacl);
      _SafeHeapRelease(pSacl);

      MessageBox(NULL, TEXT("Unable to convert SD."), TEXT("Error"), MB_OK | MB_ICONERROR);
      return FALSE;
   }

   return TRUE;
}

VOID
CSecInfoTS::DisplaySDDL (
   _In_ PSECURITY_DESCRIPTOR pSecurityDescriptor
)
{
   BOOL bResult;
   DWORD dwSize;
   LPTSTR szSDDL;

   bResult = ConvertSecurityDescriptorToStringSecurityDescriptor(
      pSecurityDescriptor,
      SDDL_REVISION_1,
      DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION,
      &szSDDL,
      &dwSize
   );

   if (bResult)
   {
      MessageBox(NULL, szSDDL, TEXT("SDDL"), MB_OK);
      LocalFree(szSDDL);
   }
}
