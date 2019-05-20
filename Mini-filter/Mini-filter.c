/*++

Module Name:

    Minifilter.c

Abstract:

    This is the main module of the Mini-filter miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <ntstrsafe.h>
#include <wdm.h>
#include <malloc.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 1;

#define PT_DBG_PRINT(_dbgLevel, _string) (gTraceFlags ? DbgPrint _string : 0)

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
MinifilterInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
MinifilterInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
MinifilterInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
MinifilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
MinifilterInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
MinifilterPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
MinifilterOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
MinifilterPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
MinifilterPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
MinifilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

FLT_PREOP_CALLBACK_STATUS
ReadFilePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
WriteFilePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
ReadFilePostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_POSTOP_CALLBACK_STATUS
WriteFilePostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, MinifilterUnload)
#pragma alloc_text(PAGE, MinifilterInstanceQueryTeardown)
#pragma alloc_text(PAGE, MinifilterInstanceSetup)
#pragma alloc_text(PAGE, MinifilterInstanceTeardownStart)
#pragma alloc_text(PAGE, MinifilterInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_CLOSE,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_READ,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_WRITE,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_SET_EA,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      MinifilterPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_PNP,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      MinifilterPreOperation,
      MinifilterPostOperation },

#endif // TODO

	{ IRP_MJ_READ,
	  0,
	  ReadFilePreOperation,
	  NULL },

	{ IRP_MJ_WRITE,
	  0,
	  WriteFilePreOperation,
	  NULL },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    MinifilterUnload,                           //  MiniFilterUnload

    MinifilterInstanceSetup,                    //  InstanceSetup
    MinifilterInstanceQueryTeardown,            //  InstanceQueryTeardown
    MinifilterInstanceTeardownStart,            //  InstanceTeardownStart
    MinifilterInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
MinifilterInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Minifilter!MinifilterInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
MinifilterInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Minifilter!MinifilterInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
MinifilterInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Minifilter!MinifilterInstanceTeardownStart: Entered\n") );
}


VOID
MinifilterInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Minifilter!MinifilterInstanceTeardownComplete: Entered\n") );
}

/* --- */

UNICODE_STRING configRules;

NTSTATUS ReadConfig()
{
	HANDLE			  handle;
	NTSTATUS		  ntstatus;
	IO_STATUS_BLOCK   ioStatusBlock;
	LARGE_INTEGER     byteOffset;

	UNICODE_STRING    confFilePath;
	OBJECT_ATTRIBUTES objAttr;

	configRules.Length = 0;
	configRules.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	configRules.Buffer = ExAllocatePoolWithTag(NonPagedPool, configRules.MaximumLength, '2gaT');
	if (configRules.Buffer == NULL)
	{
		DbgPrint("CRDriver: ERROR: Can't allocate memory for config file!\n");
		return STATUS_FILE_CORRUPT_ERROR;
	} else
		RtlZeroMemory(configRules.Buffer, configRules.MaximumLength);

	RtlInitUnicodeString(&confFilePath, L"\\??\\C:\\CRDriver.conf");
	InitializeObjectAttributes(&objAttr, &confFilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	ntstatus = ZwCreateFile(
		&handle,
		GENERIC_READ,
		&objAttr, &ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);

	if (NT_SUCCESS(ntstatus))
	{
		byteOffset.LowPart = byteOffset.HighPart = 0;
		ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock, configRules.Buffer, configRules.MaximumLength, &byteOffset, NULL);
		if (NT_SUCCESS(ntstatus))
		{
			RtlStringCbLengthA((STRSAFE_PCNZCH) configRules.Buffer, configRules.MaximumLength, (size_t *) &configRules.Length);
			configRules.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
			
			// Эта функция читает в ANSI. Преобразуем в UNICODE.
			ANSI_STRING tmpS;
			tmpS.Length = configRules.Length;
			tmpS.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
			tmpS.Buffer = ExAllocatePoolWithTag(NonPagedPool, tmpS.MaximumLength, '4gaT');
			if (tmpS.Buffer == NULL)
			{
				DbgPrint("CRDriver: ERROR: Can't allocate memory. Driver not started.\n");
				return STATUS_DEVICE_CONFIGURATION_ERROR;
			}
			RtlCopyMemory(tmpS.Buffer, configRules.Buffer, configRules.MaximumLength);
			RtlZeroMemory(configRules.Buffer, configRules.MaximumLength);

			if (STATUS_SUCCESS != RtlAnsiStringToUnicodeString(&configRules, &tmpS, FALSE))
				DbgPrint("CRDriver: ERROR: RtlAnsiStringToUnicodeString error!\n");

			//DbgPrint("CRDriver: CRDebug: %d %d %ws", configRules.Length, configRules.MaximumLength, configRules.Buffer);
			//DbgPrint("CRDriver: CRDebug: %d %d %s", tmpS.Length, tmpS.MaximumLength, tmpS.Buffer);

			ExFreePool(tmpS.Buffer);
		}

		ZwClose(handle);
		return STATUS_SUCCESS;
	} else
	{
		ExFreePool(configRules.Buffer);
		configRules.Buffer = NULL;
		DbgPrint("CRDriver: ERROR: Can't read config file!\n");
		return STATUS_FILE_CORRUPT_ERROR;
	}
}

VOID FreeConfig()
{
	if (configRules.Buffer != NULL)
	{
		ExFreePool(configRules.Buffer);
		configRules.Buffer = NULL;
	}
}

NTSTATUS checkAccessRule(CHAR operation, UNICODE_STRING currentProcess, UNICODE_STRING currentObject)
{
	if (configRules.Buffer == NULL || configRules.Length == 0) return STATUS_SUCCESS;
	
	PWSTR ptr = configRules.Buffer;
	int entryCounter = 0; // Счетчик строк.
	int foundQuarantineDir, foundFileName, foundNewLine, foundOperations, foundReadRule, foundWriteRule;

	UNICODE_STRING tmpProcessName; // Имя текущего процесса из CONF файла.
	tmpProcessName.Length = 0;
	tmpProcessName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	tmpProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool, tmpProcessName.MaximumLength, '5gaT');
	if (tmpProcessName.Buffer == NULL)
	{
		DbgPrint("CRDriver: ERROR: checkAccessRule: Can't allocate memory for tmpProcessName. Returning STATUS_SUCCESS.\n");
		return STATUS_SUCCESS;
	} else
		RtlZeroMemory(tmpProcessName.Buffer, tmpProcessName.MaximumLength);
	
	UNICODE_STRING tmpObjectFileName; // Имя текущего объекта для текущего процесса из CONF файла.
	tmpObjectFileName.Length = 0;
	tmpObjectFileName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	tmpObjectFileName.Buffer = ExAllocatePoolWithTag(NonPagedPool, tmpObjectFileName.MaximumLength, '8gaT');
	if (tmpObjectFileName.Buffer == NULL)
	{
		DbgPrint("CRDriver: ERROR: checkAccessRule: Can't allocate memory for tmpObjectName. Returning STATUS_SUCCESS.\n");
		ExFreePool(tmpProcessName.Buffer);
		return STATUS_SUCCESS;
	} else
		RtlZeroMemory(tmpObjectFileName.Buffer, tmpObjectFileName.MaximumLength);

	UNICODE_STRING quarantineDir; // Папка-карантин. Определяем ее также из CONF файла.
	quarantineDir.Length = 0;
	quarantineDir.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	quarantineDir.Buffer = ExAllocatePoolWithTag(NonPagedPool, quarantineDir.MaximumLength, '9gaT');
	if (quarantineDir.Buffer == NULL)
	{
		DbgPrint("CRDriver: ERROR: checkAccessRule: Can't allocate memory for quarantineDir. Returning STATUS_SUCCESS.\n");
		ExFreePool(tmpProcessName.Buffer);
		ExFreePool(tmpObjectFileName.Buffer);
		return STATUS_SUCCESS;
	} else
		RtlZeroMemory(quarantineDir.Buffer, quarantineDir.MaximumLength);

	// beg --- Парсим название директории-карантина.

	foundQuarantineDir = FALSE;
	while (*ptr != L'\0')
	{
		while (*ptr == L'\r' || *ptr == L'\n')
		{
			foundQuarantineDir = TRUE;
			ptr++;
		}

		if (foundQuarantineDir) break;

		if (quarantineDir.Length + sizeof(WCHAR) < quarantineDir.MaximumLength)
		{
			quarantineDir.Buffer[quarantineDir.Length / sizeof(WCHAR)] = *ptr;
			quarantineDir.Length += sizeof(WCHAR);
		} else
			DbgPrint("CRDriver: WARNING: checkAccessRule: Too long processName in CONF file. Check CONF file.\n");

		ptr++;
	}

	DbgPrint("CRDebug: quarantineDir: %d %ws\n", quarantineDir.Length, quarantineDir.Buffer);
	DbgPrint("CRDebug: currentObject: %d %ws\n", currentObject.Length, currentObject.Buffer);

	// Сразу отбрасываем объекты, не принадлежащие директории папки-карантина (разрешаем доступ).
	if (currentObject.Length < quarantineDir.Length)
	{
		ExFreePool(tmpProcessName.Buffer);
		ExFreePool(tmpObjectFileName.Buffer);
		ExFreePool(quarantineDir.Buffer);
		return STATUS_SUCCESS;
	}
	PWSTR ptr1 = configRules.Buffer, ptr2 = currentObject.Buffer;
	for (int i = 0; i < quarantineDir.Length / sizeof(WCHAR); i++)
		if (ptr1[i] != ptr2[i])
		{
			ExFreePool(tmpProcessName.Buffer);
			ExFreePool(tmpObjectFileName.Buffer);
			ExFreePool(quarantineDir.Buffer);
			return STATUS_SUCCESS;
		}

	UNICODE_STRING currentObjectFileName; // Название файла относительно папки-карантина (отбрасываем лишний путь).
	currentObjectFileName.Length = currentObject.Length - quarantineDir.Length;
	currentObjectFileName.MaximumLength = currentObject.Length - quarantineDir.Length + sizeof(WCHAR);
	currentObjectFileName.Buffer = ExAllocatePoolWithTag(NonPagedPool, currentObjectFileName.MaximumLength, '7gaT');
	if (currentObjectFileName.Buffer == NULL)
	{
		DbgPrint("CRDriver: ERROR: checkAccessRule: Can't allocate memory for currentObjectFileName. Returning STATUS_SUCCESS.\n");
		
		ExFreePool(tmpProcessName.Buffer);
		ExFreePool(tmpObjectFileName.Buffer);
		ExFreePool(quarantineDir.Buffer);
		return STATUS_SUCCESS;
	} else
	{
		RtlZeroMemory(currentObjectFileName.Buffer, currentObjectFileName.MaximumLength);
		size_t offset = 0;
		if (currentObject.Buffer[quarantineDir.Length / sizeof(WCHAR)] == L'\\')
		{
			offset += sizeof(WCHAR);
			currentObjectFileName.Length -= sizeof(WCHAR);
		}
		RtlCopyMemory(currentObjectFileName.Buffer, currentObject.Buffer + (quarantineDir.Length + offset) / sizeof(WCHAR), currentObjectFileName.Length);
	}

	DbgPrint("CRDebug: currentObjectFileName: %d %ws\n", currentObjectFileName.Length, currentObjectFileName.Buffer);

	// end --- Парсим название директории-карантина.

	foundFileName = foundOperations = foundReadRule = foundWriteRule = FALSE;

iter:
	if (foundOperations)
	{
		DbgPrint("CRDebug: %d %d currentProc: %ws\n", currentProcess.Length, currentProcess.MaximumLength, currentProcess.Buffer);
		DbgPrint("CRDebug: %d %d tmpProcessName: %ws\n", tmpProcessName.Length, currentProcess.MaximumLength, tmpProcessName.Buffer);
		DbgPrint("CRDebug: %d %d tmpObjectName: %ws\n", tmpObjectFileName.Length, tmpObjectFileName.MaximumLength, tmpObjectFileName.Buffer);
	}

	if (foundOperations // Основная проверка на доступ после парсинга.
		&& RtlEqualUnicodeString(&currentProcess, &tmpProcessName, TRUE)
		&& RtlEqualUnicodeString(&currentObjectFileName, &tmpObjectFileName, TRUE))
	{
		//DbgPrint("CRDebug: LOL, %c, foundReadRule=%d, foundWriteRule=%d\n", operation, foundReadRule, foundWriteRule);
		if (operation == 'r' && foundReadRule) goto status_success;
		if (operation == 'w' && foundWriteRule) goto status_success;

		foundFileName = foundOperations = foundReadRule = foundWriteRule = FALSE;
		RtlZeroMemory(tmpProcessName.Buffer, tmpProcessName.MaximumLength);
		tmpProcessName.Length = 0;
		RtlZeroMemory(tmpObjectFileName.Buffer, tmpObjectFileName.MaximumLength);
		tmpObjectFileName.Length = 0;
	}

	while (*ptr != L'\0')
	{
		{
			foundNewLine = FALSE;
			while (*ptr == L'\r' || *ptr == L'\n')
			{
				foundNewLine = TRUE;
				ptr++;
			}

			if (foundNewLine)
			{
				foundFileName = foundOperations = foundReadRule = foundWriteRule = FALSE;
				RtlZeroMemory(tmpProcessName.Buffer, tmpProcessName.MaximumLength);
				tmpProcessName.Length = 0;
				RtlZeroMemory(tmpObjectFileName.Buffer, tmpObjectFileName.MaximumLength);
				tmpObjectFileName.Length = 0;

				entryCounter++;
				goto iter;
			}
		}

		{
			// Будем парсить название объекта, доступ к которому определили в CONF файле.
			if (!foundFileName) 
				while (*ptr == L':')
				{
					foundFileName = TRUE;
					ptr++;
				}

			// Парсим права доступа.
			while (*ptr == L':')
			{
				foundOperations = TRUE;
				ptr++;
			}

			if (foundOperations)
			{
				while (*ptr == L'r' || *ptr == L'w' || *ptr == L'R' || *ptr == L'W')
				{
					if (*ptr == L'r' || *ptr == L'R') foundReadRule = TRUE;
					else if (*ptr == L'w' || *ptr == L'W') foundWriteRule = TRUE;
					ptr++;
				}

				goto iter;
			}
		}

		if (!foundFileName) // Заполняем название процесса.
		{
			if (tmpProcessName.Length + sizeof(WCHAR) < tmpProcessName.MaximumLength)
			{
				tmpProcessName.Buffer[tmpProcessName.Length / sizeof(WCHAR)] = *ptr;
				tmpProcessName.Length += sizeof(WCHAR);
			} else
				DbgPrint("CRDriver: WARNING: checkAccessRule: Too long processName in CONF file. Check CONF file.\n");
		} else // Заполняем название объекта, доступ к которому определили в CONF файле.
		{
			if (tmpObjectFileName.Length + sizeof(WCHAR) < tmpObjectFileName.MaximumLength)
			{
				tmpObjectFileName.Buffer[tmpObjectFileName.Length / sizeof(WCHAR)] = *ptr;
				tmpObjectFileName.Length += sizeof(WCHAR);
			} else
				DbgPrint("CRDriver: WARNING: checkAccessRule: Too long tmpObjectName in CONF file. Check CONF file.\n");
		}

		ptr++;
	}

	ExFreePool(tmpProcessName.Buffer);
	ExFreePool(tmpObjectFileName.Buffer);
	ExFreePool(quarantineDir.Buffer);
	ExFreePool(currentObjectFileName.Buffer);
	return STATUS_ACCESS_DENIED;
	  
status_success:
	ExFreePool(tmpProcessName.Buffer);
	ExFreePool(tmpObjectFileName.Buffer);
	ExFreePool(quarantineDir.Buffer);
	ExFreePool(currentObjectFileName.Buffer);
	return STATUS_SUCCESS;
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Minifilter!DriverEntry: Entered\n") );

	if (NT_SUCCESS(ReadConfig()))
	{
		DbgPrint("CRDriver: Configuration finished. Content: %ws", configRules.Buffer);
	} else
	{
		DbgPrint("CRDriver: ERROR: Driver configuration was failed. Driver not started.");
		return STATUS_DEVICE_CONFIGURATION_ERROR;
	}

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status ))
	{

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    } else
	{
		DbgPrint("CRDriver: DriverEntry: driver is not started! Status: %08x\n", status);
		return status;
	}

    return status;
}

NTSTATUS
MinifilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Minifilter!MinifilterUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

	FreeConfig();

    return STATUS_SUCCESS;
}

/* --- */

typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

QUERY_INFO_PROCESS ZwQueryInformationProcess;

NTSTATUS GetProcessImageName(PUNICODE_STRING ProcessImageName)
{
    NTSTATUS status;
    ULONG returnedLength;
    ULONG bufferLength;
    PVOID buffer;
    PUNICODE_STRING imageName;
    
    PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

    if (NULL == ZwQueryInformationProcess)
	{
        UNICODE_STRING routineName;

        RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
        ZwQueryInformationProcess = (QUERY_INFO_PROCESS) MmGetSystemRoutineAddress(&routineName);

        if (NULL == ZwQueryInformationProcess)
            DbgPrint("CRDriver: Cannot resolve ZwQueryInformationProcess\n");
    }
    //
    // Step one - get the size we need
    //
    status = ZwQueryInformationProcess( NtCurrentProcess(), 
                                        ProcessImageFileName,
                                        NULL, // buffer
                                        0, // buffer size
                                        &returnedLength);

    if (STATUS_INFO_LENGTH_MISMATCH != status)
        return status;

    //
    // Is the passed-in buffer going to be big enough for us?  
    // This function returns a single contguous buffer model...
    //
    bufferLength = returnedLength - sizeof(UNICODE_STRING);
    
    if (ProcessImageName->MaximumLength < bufferLength)
	{
        ProcessImageName->Length = (USHORT) bufferLength;
        return STATUS_BUFFER_OVERFLOW;
    }

    //
    // If we get here, the buffer IS going to be big enough for us, so 
    // let's allocate some storage.
    //
    buffer = ExAllocatePoolWithTag(PagedPool, returnedLength, 'ipgD');

    if (NULL == buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    //
    // Now lets go get the data
    //
    status = ZwQueryInformationProcess( NtCurrentProcess(), 
                                        ProcessImageFileName,
                                        buffer,
                                        returnedLength,
                                        &returnedLength);

    if (NT_SUCCESS(status))
	{
        //
        // Ah, we got what we needed
        //
        imageName = (PUNICODE_STRING) buffer;

        RtlCopyUnicodeString(ProcessImageName, imageName);
    }

    //
    // free our buffer
    //
    ExFreePool(buffer);

    //
    // And tell the caller what happened.
    //    
    return status;
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS
ReadFilePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	NTSTATUS status;
	UNICODE_STRING processName;
	ULONG memoryTag = '1gaT';

	if (FLT_IS_FS_FILTER_OPERATION(Data))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (FltObjects->FileObject == NULL || Data == NULL)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (Data->Iopb->TargetFileObject == NULL || Data->Iopb->MajorFunction != IRP_MJ_READ)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	processName.Length = 0;
	processName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	processName.Buffer = ExAllocatePoolWithTag(NonPagedPool, processName.MaximumLength, memoryTag);
	if (processName.Buffer == NULL)
	{
		DbgPrint("CRDriver: ERROR: Can't allocate memory for processName!");
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	RtlZeroMemory(processName.Buffer, processName.MaximumLength);
	status = GetProcessImageName(&processName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("CRDriver: ERROR: GetProcessImageName\n");
		ExFreePoolWithTag(processName.Buffer, memoryTag);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (processName.Length == 0)
	{
		ExFreePoolWithTag(processName.Buffer, memoryTag);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!NT_SUCCESS(checkAccessRule('r', processName, Data->Iopb->TargetFileObject->FileName)))
	{
		DbgPrint("CRDriver: READ ACCESS DENIED: (%d %d) %ws TO (%d %d) %ws\n", processName.Length, processName.MaximumLength, processName.Buffer, Data->Iopb->TargetFileObject->FileName.Length, Data->Iopb->TargetFileObject->FileName.MaximumLength, Data->Iopb->TargetFileObject->FileName.Buffer);
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		ExFreePoolWithTag(processName.Buffer, memoryTag);
		return FLT_PREOP_COMPLETE;
	} else
	{
		DbgPrint("CRDriver: READ ACCESS GRANTED: (%d %d) %ws TO (%d %d) %ws\n", processName.Length, processName.MaximumLength, processName.Buffer, Data->Iopb->TargetFileObject->FileName.Length, Data->Iopb->TargetFileObject->FileName.MaximumLength, Data->Iopb->TargetFileObject->FileName.Buffer);
	}

	ExFreePoolWithTag(processName.Buffer, memoryTag);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
WriteFilePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	NTSTATUS status;
	UNICODE_STRING processName;
	ULONG memoryTag = '6gaT';

	if (FLT_IS_FS_FILTER_OPERATION(Data))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (FltObjects->FileObject == NULL || Data == NULL)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (Data->Iopb->TargetFileObject == NULL || Data->Iopb->MajorFunction != IRP_MJ_WRITE)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	processName.Length = 0;
	processName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	processName.Buffer = ExAllocatePoolWithTag(NonPagedPool, processName.MaximumLength, memoryTag);
	if (processName.Buffer == NULL)
	{
		DbgPrint("CRDriver: ERROR: Can't allocate memory for processName!");
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	RtlZeroMemory(processName.Buffer, processName.MaximumLength);
	status = GetProcessImageName(&processName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("CRDriver: ERROR: GetProcessImageName\n");
		ExFreePoolWithTag(processName.Buffer, memoryTag);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (processName.Length == 0)
	{
		ExFreePoolWithTag(processName.Buffer, memoryTag);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (!NT_SUCCESS(checkAccessRule('w', processName, Data->Iopb->TargetFileObject->FileName)))
	{
		DbgPrint("CRDriver: WRITE ACCESS DENIED: (%d %d) %ws TO (%d %d) %ws\n", processName.Length, processName.MaximumLength, processName.Buffer, Data->Iopb->TargetFileObject->FileName.Length, Data->Iopb->TargetFileObject->FileName.MaximumLength, Data->Iopb->TargetFileObject->FileName.Buffer);
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		ExFreePoolWithTag(processName.Buffer, memoryTag);
		return FLT_PREOP_COMPLETE;
	} else
	{
		DbgPrint("CRDriver: WRITE ACCESS GRANTED: (%d %d) %ws TO (%d %d) %ws\n", processName.Length, processName.MaximumLength, processName.Buffer, Data->Iopb->TargetFileObject->FileName.Length, Data->Iopb->TargetFileObject->FileName.MaximumLength, Data->Iopb->TargetFileObject->FileName.Buffer);
	}

	ExFreePoolWithTag(processName.Buffer, memoryTag);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
MinifilterPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Minifilter!MinifilterPreOperation: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (MinifilterDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    MinifilterOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("Minifilter!MinifilterPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

VOID
MinifilterOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Minifilter!MinifilterOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("Minifilter!MinifilterOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
MinifilterPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Minifilter!MinifilterPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
MinifilterPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("Minifilter!MinifilterPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
MinifilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}
