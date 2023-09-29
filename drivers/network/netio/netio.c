/* This file is (c) Johannes Thoma 2023 and is licensed under the GPL v2 */

#define _WINBASE_
#define _WINDOWS_H
#define _INC_WINDOWS

#include <windef.h>
#include <wsk.h>

static NTSTATUS WskSocket(
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
	DbgPrint("Not implemented");
	return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS WskSocketConnect(
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
	DbgPrint("Not implemented");
	return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS WskControlClient(
    _In_ PWSK_CLIENT Client,
    _In_ ULONG ControlCode,
    _In_ SIZE_T InputSize,
    _In_reads_bytes_opt_(InputSize) PVOID InputBuffer,
    _In_ SIZE_T OutputSize,
    _Out_writes_bytes_opt_(OutputSize) PVOID OutputBuffer,
    _Out_opt_ SIZE_T *OutputSizeReturned,
    _Inout_opt_ PIRP Irp)
{
	DbgPrint("Not implemented");
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

