/* This file is (c) Johannes Thoma 2023 and is licensed under the GPL v2 */

/* We are a NT6+ driver .. */
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x600
#undef WINVER
#define WINVER 0x600

#include <ntdef.h>
#include <wdm.h>
#include <wsk.h>
#include <ndis.h>

#include <tdi.h>
#include <tcpioctl.h>
#include <tdikrnl.h>
#include <tdiinfo.h>
#include "tdi_proto.h"
#include "tdiconn.h"

struct _WSK_SOCKET_INTERNAL {
	struct _WSK_SOCKET s;

	ADDRESS_FAMILY family;	/* AF_INET or AF_INET6 */
	unsigned short type;	/* SOCK_DGRAM, SOCK_STREAM, ... */
	unsigned long proto; /* IPPROTO_UDP, IPPROTO_TCP */
	unsigned long flags;	/* WSK_FLAG_LISTEN_SOCKET, ... */
	void *user_context;  /* parameter for callbacks, opaque */

	struct _FILE_OBJECT *file; /* Returned by TdiOpenConnectionEndpointFile() */
	HANDLE handle; /* Returned by TdiOpenConnectionEndpointFile() */
};

NTSTATUS NTAPI
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DbgPrint("netio.sys DriverEntry ...\n");

	return STATUS_SUCCESS;
}

static WSKAPI NTSTATUS WskSocket(
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
			DbgPrint("SOCK_RAW not supported.\n"); /* fallthru */
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
	// DbgPrint("WskSocket Not implemented\n");
	return STATUS_NOT_IMPLEMENTED;
}

static WSKAPI NTSTATUS WskSocketConnect(
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

static WSKAPI NTSTATUS WskControlClient(
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
DbgPrint("WskRegister\n");
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

