// SPDX-License-Identifier: GPL-2.0-or-later

/* This file is (c) Johannes Thoma <johannes@johannesthoma.com 2023-2024
   It is licensed under the GPL v2.
 */

/* We are a NT6+ driver .. */
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x600
#undef WINVER
#define WINVER 0x600

/* TODOs:
	Done: Clean up socket in WskCloseSocket (have RefCount and
	SocketGet / SocketPut functions).
	Done: Remove unnecessary code (like Hook of completion)
	Make it compile with MS VC as well
	Rebase onto latest master
	Squash commits (git rebase -i) one for tdihelpers one for netio

	The whole Listen / Accept mechanism is still missing
	Some minor functions (not used by WinDRBD) are missing
	(like WskControlClient, WskSocketConnect, ...)
	Raw sockets are not supported for now.
	We should have regression tests for that...
*/

#include <ntdef.h>
#include <wdm.h>
#include <wsk.h>
#include <ndis.h>
#include <ntifs.h>
#include <windef.h>
/* From afd: this should be removed: */
#include <debug.h>

#include <tdi.h>
#include <tcpioctl.h>
#include <tdikrnl.h>
#include <tdiinfo.h>
#include <tdi_proto.h>
#include <tdiconn.h>

/* AFD also defines this. It is used by the tdi helpers */
DWORD DebugTraceLevel = MIN_TRACE;

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE ((HANDLE) -1)
#endif

#ifndef TAG_AFD_TDI_CONNECTION_INFORMATION
#define TAG_AFD_TDI_CONNECTION_INFORMATION 'cTfA'
#endif

/* AFD Share Flags */
#define AFD_SHARE_UNIQUE		0x0L
#define AFD_SHARE_REUSE			0x1L
#define AFD_SHARE_WILDCARD		0x2L
#define AFD_SHARE_EXCLUSIVE		0x3L

struct _WSK_SOCKET_INTERNAL {
	struct _WSK_SOCKET s;

	ADDRESS_FAMILY family;	/* AF_INET or AF_INET6 */
	unsigned short type;	/* SOCK_DGRAM, SOCK_STREAM, ... */
	unsigned long proto; /* IPPROTO_UDP, IPPROTO_TCP */
	unsigned long flags;	/* WSK_FLAG_LISTEN_SOCKET, ... */
	void *user_context;  /* parameter for callbacks, opaque */
	struct _UNICODE_STRING TdiName;	/* \\Devices\\Tcp, \\Devices\\Udp */

	struct sockaddr LocalAddress;
	PFILE_OBJECT LocalAddressFile;
	HANDLE LocalAddressHandle;

	struct sockaddr RemoteAddress;	/* Remeber latest remote connection */

		/* Those exist for connection oriented (TCP/IP) sockets only */
	PFILE_OBJECT ConnectionFile; /* Returned by TdiOpenConnectionEndpointFile() */
	HANDLE ConnectionHandle; /* Returned by TdiOpenConnectionEndpointFile() */

		/* Incoming connection callback function: */
	const struct _WSK_CLIENT_LISTEN_DISPATCH *ListenDispatch;
	int CallbackMask;

	int Flags;	/* SO_REUSEADDR, ... see ws2def.h */
		/* TODO: we have refcounting now, this should go away: */
	LIST_ENTRY PendingUserIrps;  /* Irps we got from our user.
					For cancelling in WskClose () */
	int RefCount;	/* See SocketGet/SocketPut TODO: this should be atomic */
};

struct NetioContext {
	PIRP UserIrp;
	struct _WSK_SOCKET_INTERNAL *socket;
};

void SocketGet(struct _WSK_SOCKET_INTERNAL *s)
{
	s->RefCount++;
}

void SocketPut(struct _WSK_SOCKET_INTERNAL *s)
{
		/* TODO: get some spinlock */
	s->RefCount--;
	if (s->RefCount == 0) {
		if (s->LocalAddressHandle != INVALID_HANDLE_VALUE) {
			ZwClose(s->LocalAddressHandle);
			s->LocalAddressHandle = INVALID_HANDLE_VALUE;
			s->LocalAddressFile = NULL;
		}
		if (s->ConnectionHandle != INVALID_HANDLE_VALUE) {
			ZwClose(s->ConnectionHandle);
			s->ConnectionHandle = INVALID_HANDLE_VALUE;
			s->ConnectionFile = NULL;
		}
		/* TODO: Free TdiName and others ... */
DbgPrint("NetIO: about to free socket %p ...\n", s);
		ExFreePoolWithTag(s, 'SOCK');
	}
}

	/* This just sets the status to pending. It is been called
	 * by the IoCallDriver() function via the MajorFunction
	 * dispatch table in the DriverObject. We need this because
	 * we want to use IoCallDriver to consume one stack location
	 * of the irp. If we do not do so the completion routine of
	 * the upper driver never gets called.
	 */

static NTSTATUS NTAPI DummyHandler(PDEVICE_OBJECT Device, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_PENDING;

	return STATUS_PENDING;
}

struct DummyDeviceExtension { int x; };

PDEVICE_OBJECT DummyDeviceObject;

static NTSTATUS DummyCallDriver(PIRP Irp)
{
	return IoCallDriver(DummyDeviceObject, Irp);
}

NTSTATUS NTAPI
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	int i;
	NTSTATUS status;
	UNICODE_STRING nameUnicode;

	DbgPrint("netio.sys DriverEntry compiled " __DATE__ " " __TIME__ " ...\n");

	for (i=0; i<=IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DummyHandler;

	RtlInitUnicodeString(&nameUnicode, L"\\Device\\NetioSysDummy");

	status = IoCreateDevice(DriverObject, sizeof(struct DummyDeviceExtension),
				&nameUnicode, FILE_DEVICE_UNKNOWN,
				FILE_DEVICE_SECURE_OPEN, FALSE, &DummyDeviceObject);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Can't create root, err=%x\n", status);
		return status;
	}
	return STATUS_SUCCESS;
}

static NTSTATUS NTAPI NetioComplete(
  PDEVICE_OBJECT DeviceObject,
  PIRP Irp,
  PVOID Context)
{
	struct NetioContext *c = (struct NetioContext*) Context;
	PIRP UserIrp = c->UserIrp;

// DbgPrint("NetioComplete Irp is %p UserIrp is %p Status is 0x%08x\n", Irp, UserIrp, Irp->IoStatus.Status);

	UserIrp->IoStatus.Status = Irp->IoStatus.Status;
	UserIrp->IoStatus.Information = Irp->IoStatus.Information;

	RemoveEntryList(&UserIrp->Tail.Overlay.ListEntry);
	IoCompleteRequest(UserIrp, IO_NETWORK_INCREMENT);

	SocketPut(c->socket);
	ExFreePoolWithTag(c, 'NEIO');

	return STATUS_SUCCESS;
}

static NTSTATUS WSKAPI WskControlSocket(
    _In_ PWSK_SOCKET Socket,
    _In_ WSK_CONTROL_SOCKET_TYPE RequestType,
    _In_ ULONG ControlCode,
    _In_ ULONG Level,
    _In_ SIZE_T InputSize,
    _In_reads_bytes_opt_(InputSize) PVOID InputBuffer,
    _In_ SIZE_T OutputSize,
    _Out_writes_bytes_opt_(OutputSize) PVOID  OutputBuffer,
    _Out_opt_ SIZE_T *OutputSizeReturned,
    _Inout_opt_ PIRP Irp)
{
	struct _WSK_SOCKET_INTERNAL *s = (struct _WSK_SOCKET_INTERNAL*) Socket;
	NTSTATUS status = STATUS_NOT_IMPLEMENTED;

	if (s == NULL) {
		DbgPrint("WskControlSocket: Socket is NULL\n");
		status = STATUS_INVALID_PARAMETER;
	}
	switch (RequestType) {
	case WskSetOption:
		switch (Level) {
		case SOL_SOCKET:
			switch (ControlCode) {
			case SO_REUSEADDR:	/* add more supported flags here ... */
				if (InputBuffer == NULL) {
					DbgPrint("WskControlSocket: Need an InputBuffer for this operation\n");
					status = STATUS_INVALID_PARAMETER;
					break;
				}
				if (InputSize < 4) {
					DbgPrint("WskControlSocket: InputBuffer too small for this operation\n");
					status = STATUS_INVALID_PARAMETER;
					break;
				}
				int flag = *(int*) InputBuffer;
				if (flag != 0) {
					s->Flags |= ControlCode;
				} else {
					s->Flags &= ~ControlCode;
				}
				status = STATUS_SUCCESS;

				break;
			/* Windows specific. This sets the mask for callback functions: */
			case SO_WSK_EVENT_CALLBACK:
				if (InputBuffer == NULL) {
					DbgPrint("WskControlSocket: Need an InputBuffer for this operation\n");
					status = STATUS_INVALID_PARAMETER;
					break;
				}
				if (InputSize < sizeof(WSK_EVENT_CALLBACK_CONTROL)) {
					DbgPrint("WskControlSocket: InputBuffer too small for this operation\n");
					status = STATUS_INVALID_PARAMETER;
					break;
				}
				WSK_EVENT_CALLBACK_CONTROL *c = (WSK_EVENT_CALLBACK_CONTROL*)InputBuffer;

					/* TODO: compare this bytewise */
/*				if (c->NpiId != &NPI_WSK_INTERFACE_ID) {
					DbgPrint("WskControlSocket: Only NPI_WSK_INTERFACE_ID supported, sorry.\n");
					status = STATUS_INVALID_PARAMETER;
					break;
				} */
				s->CallbackMask = c->EventMask;
					/* TODO: and start listening here? */

				status = STATUS_SUCCESS;
				break;

			default:
				DbgPrint("WskControlSocket: ControlCode %d Not implemented.\n", ControlCode);
			}
			break;
		default:
			DbgPrint("WskControlSocket: Level %d Not implemented.\n", Level);
		}
		break;

	case WskGetOption:
	case WskIoctl:
	default:
		DbgPrint("WskControlSocket: Option %d Not implemented.\n", RequestType);
	}
	if (Irp != NULL) {
		Irp->IoStatus.Status = status;
/* ??		Irp->IoStatus.Information = Irp->IoStatus.Information; */
	}
	return status;
}

static NTSTATUS WSKAPI WskCloseSocket(
    _In_ PWSK_SOCKET Socket,
    _Inout_ PIRP Irp)
{
	struct _WSK_SOCKET_INTERNAL *s = (struct _WSK_SOCKET_INTERNAL*) Socket;

	SocketPut(s);
	/* TODO: DummyCallDriver and IoComplete */
	return STATUS_SUCCESS;
}

static struct _TRANSPORT_ADDRESS *TdiTransportAddressFromSocketAddress(PSOCKADDR SocketAddress)
{
	struct _TRANSPORT_ADDRESS *ta;

	ta = ExAllocatePoolWithTag(NonPagedPool, sizeof(*ta)+sizeof(struct sockaddr) , 'ADDR');
	if (ta == NULL) {
		DbgPrint("TdiTransportAddressFromSocketAddress: Out of memory\n");
		return NULL;
	}

//	memset(ta, 0, sizeof(*ta)+sizeof(struct sockaddr));
	ta->TAAddressCount = 1;
	ta->Address[0].AddressLength = sizeof(SocketAddress->sa_data);
	ta->Address[0].AddressType = SocketAddress->sa_family;
	memcpy(&ta->Address[0].Address[0], &SocketAddress->sa_data, ta->Address[0].AddressLength);

	return ta;
}

static PTDI_CONNECTION_INFORMATION TdiConnectionInfoFromSocketAddress(PSOCKADDR SocketAddress)
{
	PTRANSPORT_ADDRESS TargetAddress;
	PTDI_CONNECTION_INFORMATION ConnectionInformation = NULL;
	NTSTATUS status;

	TargetAddress = TdiTransportAddressFromSocketAddress(SocketAddress);
	if (TargetAddress == NULL)
		return NULL;

	status = TdiBuildConnectionInfo(&ConnectionInformation, TargetAddress);
	ExFreePoolWithTag(TargetAddress, 'ADDR');

	if (!NT_SUCCESS(status)) {
		if (ConnectionInformation != NULL) {
			ExFreePoolWithTag(ConnectionInformation, TAG_AFD_TDI_CONNECTION_INFORMATION);
		}
		return NULL;
	}
	return ConnectionInformation;
}


static NTSTATUS WSKAPI WskBind (
    _In_ PWSK_SOCKET Socket,
    _In_ PSOCKADDR LocalAddress,
    _Reserved_ ULONG Flags,
    _Inout_ PIRP Irp)
{
	NTSTATUS status;
	struct _WSK_SOCKET_INTERNAL *s = (struct _WSK_SOCKET_INTERNAL*) Socket;
	PTRANSPORT_ADDRESS ta = TdiTransportAddressFromSocketAddress(LocalAddress);
	if (ta == NULL) {
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	if (s->LocalAddressHandle != INVALID_HANDLE_VALUE) {
		ZwClose(s->LocalAddressHandle);
		s->LocalAddressHandle = INVALID_HANDLE_VALUE;
		s->LocalAddressFile = NULL;
	}

	status = TdiOpenAddressFile(&s->TdiName,
		ta,
		AFD_SHARE_REUSE,
		&s->LocalAddressHandle,
		&s->LocalAddressFile);

	if (NT_SUCCESS(status)) {
		memcpy(&s->LocalAddress, LocalAddress, sizeof(s->LocalAddress));
	}
	ExFreePoolWithTag(ta, 'ADDR');

	Irp->IoStatus.Status = status;
	return status;
}

enum direction {
	DIR_SEND,
	DIR_RECEIVE
};

static NTSTATUS WSKAPI WskSendTo (
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_BUF Buffer,
    _Reserved_ ULONG Flags,
    _In_opt_ PSOCKADDR RemoteAddress,
    _In_ ULONG ControlInfoLength,
    _In_reads_bytes_opt_(ControlInfoLength) PCMSGHDR ControlInfo,
    _Inout_ PIRP Irp)
{
	PIRP tdiIrp = NULL;
	struct _WSK_SOCKET_INTERNAL *s = (struct _WSK_SOCKET_INTERNAL*) Socket;
	PTDI_CONNECTION_INFORMATION TargetConnectionInfo;
	NTSTATUS status;
	void *BufferData;
	struct NetioContext *nc;

	if (DummyDeviceObject == NULL) {
DbgPrint("DummyDeviceObject is NULL, was the DriverEntry funtion called?\n");
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		return STATUS_INVALID_PARAMETER; /* TODO: something more meaningful */
	}

		/* Call ourselves. Sets status to pending. The interesting
		 * part happens later.
		 */

	DummyCallDriver(Irp);

	nc = ExAllocatePoolWithTag(NonPagedPool, sizeof(*nc), 'NEIO');
	if (nc == NULL) {
                Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                return STATUS_INSUFFICIENT_RESOURCES;
        }
	nc->socket = s;
	nc->UserIrp = Irp;

	TargetConnectionInfo = TdiConnectionInfoFromSocketAddress(RemoteAddress);
	if (TargetConnectionInfo == NULL) {
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	BufferData = MmGetSystemAddressForMdlSafe(Buffer->Mdl, NormalPagePriority);
	if (BufferData == NULL) {
		DbgPrint("Error mapping MDL\n");
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

		/* Some drivers (like WinDRBD) do not set this.
		 * But ReactOS seems to require this (else BSOD on completion).
		 */

	if (Irp->Tail.Overlay.Thread == NULL) {
		Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	}
	IoMarkIrpPending(Irp);
	SocketGet(s);
		/* TODO: protect by spinlock ... */
		/* TODO: still needed? */
	InsertTailList(&s->PendingUserIrps, &Irp->Tail.Overlay.ListEntry);

		/* This will create a tdiIrp: */
	status = TdiSendDatagram(&tdiIrp, s->LocalAddressFile, ((char*)BufferData)+Buffer->Offset, Buffer->Length, TargetConnectionInfo, NetioComplete, nc);

	/* TODO: check this again..I would assume if the TDI helper function
	   returns any error, the completion function is not called.
	 */
	if (!NT_SUCCESS(status)) {
		SocketPut(s);
		ExFreePoolWithTag(nc, 'NEIO');
	}
	return status;
}

static NTSTATUS WSKAPI WskReceiveFrom (
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_BUF Buffer,
    _Reserved_ ULONG Flags,
    _Out_opt_ PSOCKADDR RemoteAddress,
    _Inout_ PULONG ControlLength,
    _Out_writes_bytes_opt_(*ControlLength) PCMSGHDR ControlInfo,
    _Out_opt_ PULONG ControlFlags,
    _Inout_ PIRP Irp)
{
	DbgPrint("WskReceiveFrom: Not implemented.\n");
	return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS WSKAPI WskReleaseUdp (
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_DATAGRAM_INDICATION DatagramIndication)
{
	DbgPrint("WskReleaseUdp: Not implemented.\n");
	return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS WSKAPI WskReleaseTcp (
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_DATA_INDICATION DataIndication)
{
	DbgPrint("WskReleaseTcp: Not implemented.\n");
	return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS WSKAPI WskGetLocalAddress (
    _In_ PWSK_SOCKET Socket,
    _Out_ PSOCKADDR LocalAddress,
    _Inout_ PIRP Irp)
{
	DbgPrint("WskGetLocalAddress: Not implemented.\n");
	return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS WSKAPI WskGetRemoteAddress (
    _In_ PWSK_SOCKET Socket,
    _Out_ PSOCKADDR RemoteAddress,
    _Inout_ PIRP Irp)
{
	DbgPrint("WskGetRemoteAddress: Not implemented.\n");
	return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS WSKAPI WskSocketConnect(
    PWSK_CLIENT Client,
    USHORT SocketType,
    ULONG Protocol,
    PSOCKADDR LocalAddress,
    PSOCKADDR RemoteAddress,
    ULONG Flags,
    PVOID SocketContext,
    const WSK_CLIENT_CONNECTION_DISPATCH *Dispatch,
    PEPROCESS OwningProcess,
    PETHREAD OwningThread,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PIRP Irp)
{
	DbgPrint("WskSocketConnect Not implemented\n");
	return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS WSKAPI WskControlClient(
    _In_ PWSK_CLIENT Client,
    _In_ ULONG ControlCode,
    _In_ SIZE_T InputSize,
    _In_reads_bytes_opt_(InputSize) PVOID InputBuffer,
    _In_ SIZE_T OutputSize,
    _Out_writes_bytes_opt_(OutputSize) PVOID OutputBuffer,
    _Out_opt_ SIZE_T *OutputSizeReturned,
    _Inout_opt_ PIRP Irp)
{
	DbgPrint("WskControlClient Not implemented\n");
	return STATUS_NOT_IMPLEMENTED;
}

static struct _WSK_PROVIDER_DATAGRAM_DISPATCH UdpDispatch =
{
	.WskControlSocket = WskControlSocket,
	.WskCloseSocket = WskCloseSocket,
	.WskBind = WskBind,
	.WskSendTo = WskSendTo,
	.WskReceiveFrom = WskReceiveFrom,
	.WskRelease = WskReleaseUdp,
	.WskGetLocalAddress = WskGetLocalAddress,
};

/* Connection oriented routines (TCP/IP): */

static NTSTATUS WSKAPI WskConnect(
    _In_ PWSK_SOCKET Socket,
    _In_ PSOCKADDR RemoteAddress,
    _Reserved_ ULONG Flags,
    _Inout_ PIRP Irp)
{
	PTDI_CONNECTION_INFORMATION TargetConnectionInfo, Ignored;
	PIRP tdiIrp;
	struct _WSK_SOCKET_INTERNAL *s = (struct _WSK_SOCKET_INTERNAL*) Socket;
	NTSTATUS status;
	struct NetioContext *nc;


		/* Call ourselves. Sets status to pending. The interesting
		 * part happens later.
		 */
// DbgPrint("Irp before DummyCallDriver in WskConnect is %p\n", Irp);
	if (DummyDeviceObject == NULL) {
DbgPrint("DummyDeviceObject is NULL, was the DriverEntry funtion called?\n");
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		return STATUS_INVALID_PARAMETER; /* TODO: something more meaningful */
	}
	DummyCallDriver(Irp);

	nc = ExAllocatePoolWithTag(NonPagedPool, sizeof(*nc), 'NEIO');
	if (nc == NULL) {
                Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                return STATUS_INSUFFICIENT_RESOURCES;
        }
	nc->socket = s;
	nc->UserIrp = Irp;

	tdiIrp = NULL;

	if (s->LocalAddressHandle == INVALID_HANDLE_VALUE) {
		DbgPrint("LocalAddressHandle is not set, maybe you need to bind() your socket before connecting it?\n");
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		return STATUS_INVALID_PARAMETER;
	}

	status = TdiAssociateAddressFile(s->LocalAddressHandle, s->ConnectionFile);
	if (!NT_SUCCESS(status)) {
		Irp->IoStatus.Status = status;
		return status;
	}

	TargetConnectionInfo = TdiConnectionInfoFromSocketAddress(RemoteAddress);
	if (TargetConnectionInfo == NULL) {
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

		/* TODO: which address?? */
	Ignored = TdiConnectionInfoFromSocketAddress(RemoteAddress);
	if (Ignored == NULL) {
		ExFreePoolWithTag(TargetConnectionInfo, TAG_AFD_TDI_CONNECTION_INFORMATION);

		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

		/* Some drivers (like WinDRBD) do not set this.
		 * But ReactOS seems to require this (else BSOD on completion).
		 */

	if (Irp->Tail.Overlay.Thread == NULL) {
		Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	}
	IoMarkIrpPending(Irp);
	SocketGet(s);
	InsertTailList(&s->PendingUserIrps, &Irp->Tail.Overlay.ListEntry);

	status = TdiConnect(&tdiIrp, s->ConnectionFile, TargetConnectionInfo, Ignored, NetioComplete, nc);
	/* TODO: check this again..I would assume if the TDI helper function
	   returns any error, the completion function is not called.
	 */
	if (!NT_SUCCESS(status)) {
		SocketPut(s);
		ExFreePoolWithTag(nc, 'NEIO');
	}
	return status;
}

static NTSTATUS WSKAPI WskStreamIo(
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_BUF Buffer,
    _In_ ULONG Flags,
    _Inout_ PIRP Irp,
    enum direction Direction)
{
	PIRP tdiIrp = NULL;
	struct _WSK_SOCKET_INTERNAL *s = (struct _WSK_SOCKET_INTERNAL*) Socket;
	NTSTATUS status;
	void *BufferData;
	struct NetioContext *nc;

		/* Call ourselves. Sets status to pending. The interesting
		 * part happens later.
		 */
	DummyCallDriver(Irp);

	nc = ExAllocatePoolWithTag(NonPagedPool, sizeof(*nc), 'NEIO');
	if (nc == NULL) {
                Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                return STATUS_INSUFFICIENT_RESOURCES;
        }
	nc->socket = s;
	nc->UserIrp = Irp;

	BufferData = MmGetSystemAddressForMdlSafe(Buffer->Mdl, NormalPagePriority);
	if (BufferData == NULL) {
		DbgPrint("Error mapping MDL\n");
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

		/* Some drivers (like WinDRBD) do not set this.
		 * But ReactOS seems to require this (else BSOD on completion).
		 */

	if (Irp->Tail.Overlay.Thread == NULL) {
		Irp->Tail.Overlay.Thread = PsGetCurrentThread();
	}
	IoMarkIrpPending(Irp);
		/* TODO: protect by spinlock ... */
	InsertTailList(&s->PendingUserIrps, &Irp->Tail.Overlay.ListEntry);
	SocketGet(s);

	if (Direction == DIR_SEND) {
		/* This will create a tdiIrp: */
		status = TdiSend(&tdiIrp, s->ConnectionFile, 0, ((char*)BufferData)+Buffer->Offset, Buffer->Length, NetioComplete, nc);
	} else {
		status = TdiReceive(&tdiIrp, s->ConnectionFile, 0, ((char*)BufferData)+Buffer->Offset, Buffer->Length, NetioComplete, nc);
	}

	/* TODO: check this again..I would assume if the TDI helper function
	   returns any error, the completion function is not called.
	 */
	if (!NT_SUCCESS(status)) {
		SocketPut(s);
		ExFreePoolWithTag(nc, 'NEIO');
	}

	return status;
}

static NTSTATUS WSKAPI WskSend(
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_BUF Buffer,
    _In_ ULONG Flags,
    _Inout_ PIRP Irp)
{
	return WskStreamIo(Socket, Buffer, Flags, Irp, DIR_SEND);
}

static NTSTATUS WSKAPI WskReceive(
    _In_ PWSK_SOCKET Socket,
    _In_ PWSK_BUF Buffer,
    _In_ ULONG Flags,
    _Inout_ PIRP Irp)
{
	return WskStreamIo(Socket, Buffer, Flags, Irp, DIR_RECEIVE);
}

static NTSTATUS WSKAPI WskDisconnect(
    _In_ PWSK_SOCKET Socket,
    _In_opt_ PWSK_BUF Buffer,
    _In_ ULONG Flags,
    _Inout_ PIRP Irp)

{
	DbgPrint("WskDisconnect Not implemented\n");
	return STATUS_NOT_IMPLEMENTED;
}


static struct _WSK_PROVIDER_CONNECTION_DISPATCH TcpDispatch =
{
	.WskControlSocket = WskControlSocket,
	.WskCloseSocket = WskCloseSocket,
	.WskBind = WskBind,
	.WskConnect = WskConnect,
	.WskGetLocalAddress = WskGetLocalAddress,
	.WskGetRemoteAddress = WskGetRemoteAddress,
	.WskSend = WskSend,
	.WskReceive = WskReceive,
	.WskDisconnect = WskDisconnect,
	.WskRelease = WskReleaseTcp,
};

static NTSTATUS WSKAPI WskSocket(
    PWSK_CLIENT Client,
    ADDRESS_FAMILY AddressFamily,
    USHORT SocketType,
    ULONG Protocol,
    ULONG Flags,
    PVOID SocketContext,
    const VOID *Dispatch,
    PEPROCESS OwningProcess,
    PETHREAD OwningThread,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    PIRP Irp)
{
	struct _WSK_SOCKET_INTERNAL *s;
	NTSTATUS status;

	if (AddressFamily != AF_INET) {
		DbgPrint("Address family %d not supported (sorry only IPv4 support for now ...)\n", AddressFamily);
		return STATUS_NOT_SUPPORTED;
	}
	switch (SocketType) {
		case SOCK_DGRAM:
			if (Protocol != IPPROTO_UDP) {
				DbgPrint("SOCK_DGRAM only supports IPPROTO_UDP\n");
				return STATUS_INVALID_PARAMETER;
			}
			if (Flags != WSK_FLAG_DATAGRAM_SOCKET) {
				DbgPrint("SOCK_DGRAM flags must be WSK_FLAG_DATAGRAM_SOCKET\n");
				return STATUS_INVALID_PARAMETER;
			}
			break;

		case SOCK_STREAM:
			if (Protocol != IPPROTO_TCP) {
				DbgPrint("SOCK_STREAM only supports IPPROTO_TCP\n");
				return STATUS_INVALID_PARAMETER;
			}
			if ((Flags != WSK_FLAG_CONNECTION_SOCKET) &&
			    (Flags != WSK_FLAG_LISTEN_SOCKET)) {
				DbgPrint("SOCK_STREAM flags must be either WSK_FLAG_CONNECTION_SOCKET or WSK_FLAG_LISTEN_SOCKET\n(sorry no WSK_FLAG_STREAM_SOCKET support\n");
				return STATUS_INVALID_PARAMETER;
			}
			break;

		case SOCK_RAW:
			DbgPrint("SOCK_RAW not supported.\n");
			return STATUS_NOT_SUPPORTED;

		default:
			return STATUS_INVALID_PARAMETER;
	}

	s = ExAllocatePoolWithTag(NonPagedPool, sizeof(*s), 'SOCK');
	if (s == NULL) {
		DbgPrint("WskSocket: Out of memory\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	s->family = AddressFamily;
	s->type = SocketType;
	s->proto = Protocol;
	s->flags = Flags;
	s->user_context = SocketContext;
	s->LocalAddressHandle = INVALID_HANDLE_VALUE;
	s->LocalAddressFile = NULL;
	s->Flags = 0;
	s->ListenDispatch = Dispatch;
	s->RefCount = 1;  /* SocketPut() is in WskCloseSocket */
	s->ConnectionHandle = INVALID_HANDLE_VALUE;
	InitializeListHead(&s->PendingUserIrps);

	switch (SocketType) {
		case SOCK_DGRAM:
			s->s.Dispatch = &UdpDispatch;
			RtlInitUnicodeString(&s->TdiName, L"\\Device\\Udp");
			break;
		case SOCK_STREAM:
			s->s.Dispatch = &TcpDispatch;
			RtlInitUnicodeString(&s->TdiName, L"\\Device\\Tcp");

			status = TdiOpenConnectionEndpointFile(&s->TdiName, &s->ConnectionHandle, &s->ConnectionFile);
			if (status != STATUS_SUCCESS) {
				DbgPrint("Could not open TDI handle, status is %x.\n", status);
				ExFreePoolWithTag(s, 'SOCK');
				return status;
			}
			if (Flags == WSK_FLAG_LISTEN_SOCKET &&
			    s->ListenDispatch == NULL) {
				DbgPrint("Warning: no callbacks given for listen socket.\n");
			}
			break;

		default:
			DbgPrint("Socket type not yet supported.\n");
				/* A little bit later this probably crashes ... */
	}

	Irp->IoStatus.Information = (ULONG_PTR) s;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	return STATUS_SUCCESS;
}

static struct _WSK_PROVIDER_DISPATCH provider_dispatch = {
	.Version = 0,
	.Reserved = 0,
	.WskSocket = WskSocket,
	.WskSocketConnect = WskSocketConnect,
	.WskControlClient = WskControlClient
};

NTSTATUS
WSKAPI
WskRegister(struct _WSK_CLIENT_NPI *client_npi, struct _WSK_REGISTRATION *reg)
{
	reg->ReservedRegistrationState = 42;
	reg->ReservedRegistrationContext = NULL;
	KeInitializeSpinLock(&reg->ReservedRegistrationLock);

	return STATUS_SUCCESS;
}

NTSTATUS
WSKAPI
WskCaptureProviderNPI(struct _WSK_REGISTRATION *reg, ULONG wait, struct _WSK_PROVIDER_NPI *npi)
{
DbgPrint("WskCaptureProviderNPI\n");
	npi->Client = NULL;
	npi->Dispatch = &provider_dispatch;

	return STATUS_SUCCESS;
}

VOID
WSKAPI
WskReleaseProviderNPI(struct _WSK_REGISTRATION *reg)
{
DbgPrint("WskReleaseProviderNPI\n");
	/* noop */
}

VOID
WSKAPI
WskDeregister(struct _WSK_REGISTRATION *reg)
{
DbgPrint("WskDeregister\n");
	/* noop */
}
