;
; netio.def - export definition file for ReactOS
;
@ stdcall WskRegister(ptr ptr)
@ stdcall WskCaptureProviderNPI(ptr long ptr)
@ stdcall WskReleaseProviderNPI(ptr)
@ stdcall WskDeregister(ptr)
