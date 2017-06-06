// Take from WtsApi32.h in SDK
// We must define our value because .h in SDK is missing '|'
#define WTS_SECURITY_CURRENT_USER_ACCESS2 \
   (WTS_SECURITY_SET_INFORMATION | WTS_SECURITY_RESET | \
    WTS_SECURITY_VIRTUAL_CHANNELS | WTS_SECURITY_LOGOFF | \
    WTS_SECURITY_DISCONNECT)

SI_ACCESS TSSIAccess[] =
{
   //
   // Multiple rights
   //
   {
      &GUID_NULL,
      WTS_SECURITY_ALL_ACCESS,
      L"Full Control",
      SI_ACCESS_GENERAL | SI_ACCESS_SPECIFIC
   },

   {
      &GUID_NULL,
      WTS_SECURITY_CURRENT_GUEST_ACCESS,
      L"Current Guest Access",
      SI_ACCESS_GENERAL | SI_ACCESS_SPECIFIC
   },

   {
      &GUID_NULL,
      WTS_SECURITY_CURRENT_USER_ACCESS2,
      L"Current User Access",
      SI_ACCESS_GENERAL | SI_ACCESS_SPECIFIC
   },

   {
      &GUID_NULL,
      WTS_SECURITY_GUEST_ACCESS,
      L"Guest Access",
      SI_ACCESS_GENERAL | SI_ACCESS_SPECIFIC
   },

   {
      &GUID_NULL,
      WTS_SECURITY_USER_ACCESS,
      L"User Access",
      SI_ACCESS_GENERAL | SI_ACCESS_SPECIFIC
   },

   // Specific rights
   {
      &GUID_NULL,
      WTS_SECURITY_QUERY_INFORMATION,
      L"Query",
      SI_ACCESS_GENERAL | SI_ACCESS_SPECIFIC
   },

   {
      &GUID_NULL,
      WTS_SECURITY_SET_INFORMATION,
      L"Set Information",
      SI_ACCESS_SPECIFIC
   },

   {
      &GUID_NULL,
      WTS_SECURITY_RESET,
      L"Reset",
      SI_ACCESS_SPECIFIC
   },

   {
      &GUID_NULL,
      WTS_SECURITY_VIRTUAL_CHANNELS,
      L"Virtual Channels",
      SI_ACCESS_GENERAL | SI_ACCESS_SPECIFIC
   }, 

   {
      &GUID_NULL,
      WTS_SECURITY_REMOTE_CONTROL,
      L"Remote Control",
      SI_ACCESS_GENERAL | SI_ACCESS_SPECIFIC
   }, 

   {
      &GUID_NULL,
      WTS_SECURITY_LOGON,
      L"Logon",
      SI_ACCESS_GENERAL | SI_ACCESS_SPECIFIC
   }, 

   {
      &GUID_NULL,
      WTS_SECURITY_LOGOFF,
      L"Logoff",
      SI_ACCESS_SPECIFIC
   },

   {
      &GUID_NULL,
      WTS_SECURITY_MESSAGE,
      L"Message",
      SI_ACCESS_GENERAL | SI_ACCESS_SPECIFIC
   },

   {
      &GUID_NULL,
      WTS_SECURITY_CONNECT,
      L"Connect",
      SI_ACCESS_GENERAL | SI_ACCESS_SPECIFIC
   },

   //
   // Generic rights
   //
   {
      &GUID_NULL,
      DELETE,
      L"Delete",
      SI_ACCESS_SPECIFIC
   },

   {
      &GUID_NULL,
      READ_CONTROL,
      L"Read rights",
      SI_ACCESS_SPECIFIC
   },

   {
      &GUID_NULL,
      WRITE_DAC,
      L"Write rights",
      SI_ACCESS_SPECIFIC
   },

   {
      &GUID_NULL,
      WRITE_OWNER,
      L"Write Owner",
      SI_ACCESS_SPECIFIC
   }

   /*
   {
      &GUID_NULL,
      SYNCHRONIZE,
      L"Synchronize",
      SI_ACCESS_SPECIFIC
   },
   */
};
