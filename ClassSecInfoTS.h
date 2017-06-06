#include <aclui.h>

class CSecInfoTS : public ISecurityInformation, ISecurityInformation4
{
private:
   ULONG m_cRef;
   LPTSTR m_szListenerName;

   PSECURITY_DESCRIPTOR pRelativeSD;
   DWORD dwRelativeSDSize;

   PSECURITY_DESCRIPTOR pAbsoluteSD;
   PSID pOwner;
   PSID pPrimaryGroup;
   PACL pDacl;
   PACL pSacl;

   BOOL UpdateAbsoluteSd();
   VOID DisplaySDDL(_In_ PSECURITY_DESCRIPTOR pSecurityDescriptor);

public:
   CSecInfoTS(_In_z_ LPTSTR szListenerName);
   virtual ~CSecInfoTS();

   //
   // IUnknown methods
   //
   STDMETHOD(QueryInterface)(REFIID, void**);
   STDMETHOD_(ULONG, AddRef)();
   STDMETHOD_(ULONG, Release)();

   //
   // ISecurityInformation methods
   //
   STDMETHOD(GetObjectInformation)(PSI_OBJECT_INFO pObjectInfo);
   STDMETHOD(GetSecurity)(
      SECURITY_INFORMATION RequestedInformation,
      PSECURITY_DESCRIPTOR *ppSecurityDescriptor,
      BOOL fDefault
   );
   STDMETHOD(SetSecurity)(SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR pSecurityDescriptor);
   STDMETHOD(GetAccessRights)(
      const GUID* pguidObjectType,
      DWORD dwFlags,
      PSI_ACCESS *ppAccess,
      ULONG *pcAccesses,
      ULONG *piDefaultAccess
   );
   STDMETHOD(MapGeneric)(const GUID *pguidObjectType, UCHAR *pAceFlags, ACCESS_MASK *pMask);
   STDMETHOD(GetInheritTypes)(PSI_INHERIT_TYPE *ppInheritTypes, ULONG *pcInheritTypes);
   STDMETHOD(PropertySheetPageCallback)(HWND hwnd, UINT uMsg, SI_PAGE_TYPE uPage);

   // ISecurityInformation4 methods
   STDMETHOD(GetSecondarySecurity)(PSECURITY_OBJECT *pSecurityObjects, PULONG pSecurityObjectCount);
};