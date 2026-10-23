/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_MatanelPDB,
    0xbacaa9d0,0xf096,0x44ae,0x8c,0xfb,0xf5,0x18,0xf8,0xe9,0x91,0xfd);
// {bacaa9d0-f096-44ae-8cfb-f518f8e991fd}
