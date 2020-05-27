// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
use shared::basetsd::{INT32, SIZE_T, UINT16, ULONG_PTR};
use shared::bcrypt::{BCRYPT_NO_KEY_VALIDATION, BCryptBufferDesc};
use shared::minwindef::{BOOL, BYTE, DWORD, LPVOID, PBYTE, PUCHAR, ULONG};
use um::winnt::{HANDLE, LONG, LPCWSTR, LPWSTR, PVOID, VOID};
pub type SECURITY_STATUS = LONG;
pub type HCRYPTPROV = ULONG_PTR;
pub type HCRYPTKEY = ULONG_PTR;
pub type HCRYPTHASH = ULONG_PTR;
FN!{stdcall PFN_NCRYPT_ALLOC(
    cbSize: SIZE_T,
) -> LPVOID}
FN!{stdcall PFN_NCRYPT_FREE(
    pv: LPVOID,
) -> VOID}
STRUCT!{struct NCRYPT_ALLOC_PARA {
    cbSize: DWORD,
    pfnAlloc: PFN_NCRYPT_ALLOC,
    pfnFree: PFN_NCRYPT_FREE,
}}
pub type NCryptBufferDesc = BCryptBufferDesc;
pub type NCRYPT_HANDLE = ULONG_PTR;
pub type NCRYPT_PROV_HANDLE = ULONG_PTR;
pub type NCRYPT_KEY_HANDLE = ULONG_PTR;
pub type NCRYPT_HASH_HANDLE = ULONG_PTR;
pub type NCRYPT_SECRET_HANDLE = ULONG_PTR;
pub const NCRYPT_NO_PADDING_FLAG: DWORD = 0x00000001;
pub const NCRYPT_PAD_PKCS1_FLAG: DWORD = 0x00000002;
pub const NCRYPT_PAD_OAEP_FLAG: DWORD = 0x00000004;
pub const NCRYPT_PAD_PSS_FLAG: DWORD = 0x00000008;
pub const NCRYPT_PAD_CIPHER_FLAG: DWORD = 0x00000010;
pub const NCRYPT_ATTESTATION_FLAG: DWORD = 0x00000020;
pub const NCRYPT_SEALING_FLAG: DWORD = 0x00000100;
pub const NCRYPT_REGISTER_NOTIFY_FLAG: DWORD = 0x00000001;
pub const NCRYPT_UNREGISTER_NOTIFY_FLAG: DWORD = 0x00000002;
pub const NCRYPT_NO_KEY_VALIDATION: DWORD = BCRYPT_NO_KEY_VALIDATION;
pub const NCRYPT_MACHINE_KEY_FLAG: DWORD = 0x00000020;
pub const NCRYPT_SILENT_FLAG: DWORD = 0x00000040;
pub const NCRYPT_OVERWRITE_KEY_FLAG: DWORD = 0x00000080;
pub const NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG: DWORD = 0x00000200;
pub const NCRYPT_DO_NOT_FINALIZE_FLAG: DWORD = 0x00000400;
pub const NCRYPT_EXPORT_LEGACY_FLAG: DWORD = 0x00000800;
pub const NCRYPT_IGNORE_DEVICE_STATE_FLAG: DWORD = 0x00001000;
pub const NCRYPT_TREAT_NIST_AS_GENERIC_ECC_FLAG: DWORD = 0x00002000;
pub const NCRYPT_NO_CACHED_PASSWORD: DWORD = 0x00004000;
pub const NCRYPT_PROTECT_TO_LOCAL_SYSTEM: DWORD = 0x00008000;
pub const NCRYPT_PERSIST_ONLY_FLAG: DWORD = 0x40000000;
pub const NCRYPT_PERSIST_FLAG: DWORD = 0x80000000;
pub const NCRYPT_PREFER_VIRTUAL_ISOLATION_FLAG: DWORD = 0x00010000;
pub const NCRYPT_USE_VIRTUAL_ISOLATION_FLAG: DWORD = 0x00020000;
pub const NCRYPT_USE_PER_BOOT_KEY_FLAG: DWORD = 0x00040000;
extern "system" {
    pub fn NCryptOpenStorageProvider(
        phProvider: *mut NCRYPT_PROV_HANDLE,
        pszProviderName: LPCWSTR,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
}
STRUCT!{struct NCryptAlgorithmName {
    pszName: LPWSTR,
    dwClass: DWORD,
    dwAlgOperations: DWORD,
    dwFlags: DWORD,
}}
extern "system" {
    pub fn NCryptEnumAlgorithms(
        hProvider: NCRYPT_PROV_HANDLE,
        dwAlgOperations: DWORD,
        pdwAlgCount: *mut DWORD,
        ppAlgList: *mut *mut NCryptAlgorithmName,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptIsAlgSupported(
        hProvider: NCRYPT_PROV_HANDLE,
        pszAlgId: LPCWSTR,
        dwFlags: DWORD
    ) -> SECURITY_STATUS;
}
STRUCT!{struct NCryptKeyName {
    pszName: LPWSTR,
    pszAlgid: LPWSTR,
    dwLegacyKeySpec: DWORD,
    dwFlags: DWORD,
}}
extern "system" {
    pub fn NCryptEnumKeys(
        hProvider: NCRYPT_PROV_HANDLE,
        pszScope: LPCWSTR,
        ppKeyName: *mut *mut NCryptKeyName,
        ppEnumState: *mut PVOID,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
}
STRUCT!{struct NCryptProviderName{
    pszName: LPWSTR,
    pszComment: LPWSTR,
}}
extern "system" {
    pub fn NCryptEnumStorageProviders(
        pdwProviderCount: *mut DWORD,
        ppProviderList: *mut *mut NCryptProviderName,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptFreeBuffer(pvInput: PVOID) -> SECURITY_STATUS;
    pub fn NCryptOpenKey(
        hProvider: NCRYPT_PROV_HANDLE,
        phKey: *mut NCRYPT_KEY_HANDLE,
        pszKeyName: LPCWSTR,
        dwLegacyKeySpec: DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptCreatePersistedKey(
        hProvider: NCRYPT_PROV_HANDLE,
        phKey: *mut NCRYPT_KEY_HANDLE,
        pszAlgId: LPCWSTR,
        pszKeyName: LPCWSTR,
        dwLegacyKeySpec: DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
}
pub const NCRYPT_ALLOW_EXPORT_FLAG: DWORD = 0x00000001;
pub const NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG: DWORD = 0x00000002;
pub const NCRYPT_ALLOW_ARCHIVING_FLAG: DWORD = 0x00000004;
pub const NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG: DWORD = 0x00000008;
pub const NCRYPT_IMPL_HARDWARE_FLAG: DWORD = 0x00000001;
pub const NCRYPT_IMPL_SOFTWARE_FLAG: DWORD = 0x00000002;
pub const NCRYPT_IMPL_REMOVABLE_FLAG: DWORD = 0x00000008;
pub const NCRYPT_IMPL_HARDWARE_RNG_FLAG: DWORD = 0x00000010;
pub const NCRYPT_IMPL_VIRTUAL_ISOLATION_FLAG: DWORD = 0x00000020;
pub const NCRYPT_ALLOW_DECRYPT_FLAG: DWORD = 0x00000001;
pub const NCRYPT_ALLOW_SIGNING_FLAG: DWORD = 0x00000002;
pub const NCRYPT_ALLOW_KEY_AGREEMENT_FLAG: DWORD = 0x00000004;
pub const NCRYPT_ALLOW_KEY_IMPORT_FLAG: DWORD = 0x00000008;
pub const NCRYPT_ALLOW_ALL_USAGES: DWORD = 0x00ffffff;
pub const NCRYPT_UI_PROTECT_KEY_FLAG: DWORD = 0x00000001;
pub const NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG: DWORD = 0x00000002;
pub const NCRYPT_UI_FINGERPRINT_PROTECTION_FLAG: DWORD = 0x00000004;
pub const NCRYPT_UI_APPCONTAINER_ACCESS_MEDIUM_FLAG: DWORD = 0x00000008;
STRUCT!{struct NCRYPT_UI_POLICY {
    dwVersion: DWORD,
    dwFlags: DWORD,
    pszCreationTitle: LPCWSTR,
    pszFriendlyName: LPCWSTR,
    pszDescription: LPCWSTR,
}}
STRUCT!{struct NCRYPT_KEY_ACCESS_POLICY_BLOB {
    dwVersion: DWORD,
    dwPolicyFlags: DWORD,
    cbUserSid: DWORD,
    cbApplicationSid: DWORD,
}}
STRUCT!{struct NCRYPT_SUPPORTED_LENGTHS {
    dwMinLength: DWORD,
    dwMaxLength: DWORD,
    dwIncrement: DWORD,
    dwDefaultLength: DWORD,
}}
STRUCT!{struct NCRYPT_PCP_HMAC_AUTH_SIGNATURE_INFO {
    dwVersion: DWORD,
    iExpiration: INT32,
    pabNonce: [BYTE; 32],
    pabPolicyRef: [BYTE; 32],
    pabHMAC: [BYTE; 32],
}}
STRUCT!{struct NCRYPT_PCP_TPM_FW_VERSION_INFO {
    major1: UINT16,
    major2: UINT16,
    minor1: UINT16,
    minor2: UINT16,
}}
STRUCT!{struct NCRYPT_PCP_RAW_POLICYDIGEST_INFO {
    dwVersion: DWORD,
    cbDigest: DWORD,
}}
extern "system" {
    pub fn NCryptGetProperty(
        hObject: NCRYPT_HANDLE,
        pszProperty: LPCWSTR,
        pbOutput: PBYTE,
        cbOutput: DWORD,
        pcbResult: *mut DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptSetProperty(
        hObject: NCRYPT_HANDLE,
        pszProperty: LPCWSTR,
        pbInput: PBYTE,
        cbInput: DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptFinalizeKey(
        hKey: NCRYPT_KEY_HANDLE,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptEncrypt(
        hKey: NCRYPT_KEY_HANDLE,
        pbInput: PBYTE,
        cbInput: DWORD,
        pPaddingInfo: *const VOID,
        pbOutput: PBYTE,
        cbOutput: DWORD,
        pcbResult: *mut DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptDecrypt(
        hKey: NCRYPT_KEY_HANDLE,
        pbInput: PBYTE,
        cbInput: DWORD,
        pPaddingInfo: *const VOID,
        pbOutput: PBYTE,
        cbOutput: DWORD,
        pcbResult: *mut DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
}
STRUCT!{struct NCRYPT_KEY_BLOB_HEADER {
    cbSize: ULONG,
    dwMagic: ULONG,
    cbAlgName: ULONG,
    cbKeyData: ULONG,
}}
pub type PNCRYPT_KEY_BLOB_HEADER = *mut NCRYPT_KEY_BLOB_HEADER;
pub const NCRYPT_CIPHER_KEY_BLOB_MAGIC: DWORD = 0x52485043;
pub const NCRYPT_KDF_KEY_BLOB_MAGIC: DWORD = 0x3146444B;
pub const NCRYPT_PROTECTED_KEY_BLOB_MAGIC: DWORD = 0x4B545250;
STRUCT!{struct NCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER {
    magic: DWORD,
    cbHeader: DWORD,
    cbPublic: DWORD,
    cbPrivate: DWORD,
    cbName: DWORD,
}}
pub type PNCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER = *mut NCRYPT_TPM_LOADABLE_KEY_BLOB_HEADER;
pub const NCRYPT_TPM_LOADABLE_KEY_BLOB_MAGIC: DWORD = 0x4D54504B;
extern "system" {
    pub fn NCryptImportKey(
        hProvider: NCRYPT_PROV_HANDLE,
        hImportKey: NCRYPT_KEY_HANDLE,
        pszBlobType: LPCWSTR,
        pParameterList: *const NCryptBufferDesc,
        phKey: *mut NCRYPT_KEY_HANDLE,
        pbData: PBYTE,
        cbData: DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptExportKey(
        hKey: NCRYPT_KEY_HANDLE,
        hExportKey: NCRYPT_KEY_HANDLE,
        pszBlobType: LPCWSTR,
        pParameterList: *const NCryptBufferDesc,
        pbOutput: PBYTE,
        cbOutput: DWORD,
        pcbResult: *mut DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptSignHash(
        hKey: NCRYPT_KEY_HANDLE,
        pPaddingInfo: *const VOID,
        pbHashValue: PBYTE,
        cbHashValue: DWORD,
        pbSignature: PBYTE,
        cbSignature: DWORD,
        pcbResult: *mut DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptVerifySignature(
        hKey: NCRYPT_KEY_HANDLE,
        pPaddingInfo: *const VOID,
        pbHashValue: PBYTE,
        cbHashValue: DWORD,
        pbSignature: PBYTE,
        cbSignature: DWORD,
        dwFlags: DWORD
    ) -> SECURITY_STATUS;
    pub fn NCryptDeleteKey(
        hKey: NCRYPT_KEY_HANDLE,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptFreeObject(
        hObject: NCRYPT_HANDLE,
    ) -> SECURITY_STATUS;
    pub fn NCryptIsKeyHandle(hKey: NCRYPT_KEY_HANDLE) -> BOOL;
    pub fn NCryptTranslateHandle(
        phProvider: *mut NCRYPT_PROV_HANDLE,
        phKey: *mut NCRYPT_KEY_HANDLE,
        hLegacyProv: HCRYPTPROV,
        hLegacyKey: HCRYPTKEY,
        dwLegacyKeySpec: DWORD,
        dwFlags: DWORD
    ) -> SECURITY_STATUS;
    pub fn NCryptNotifyChangeKey(
        hProvider: NCRYPT_PROV_HANDLE,
        phEvent: *mut HANDLE,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptSecretAgreement(
        hPrivKey: NCRYPT_KEY_HANDLE,
        hPubKey: NCRYPT_KEY_HANDLE,
        phAgreedSecret: *mut NCRYPT_SECRET_HANDLE,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptDeriveKey(
        hSharedSecret: NCRYPT_SECRET_HANDLE,
        pwszKDF: LPCWSTR,
        pParameterList: *const NCryptBufferDesc,
        pbDerivedKey: PBYTE,
        cbDerivedKey: DWORD,
        pcbResult: *mut DWORD,
        dwFlags: ULONG,
    ) -> SECURITY_STATUS;
    pub fn NCryptKeyDerivation(
        hKey: NCRYPT_KEY_HANDLE,
        pParameterList: *const NCryptBufferDesc,
        pbDerivedKey: PUCHAR,
        cbDerivedKey: DWORD,
        pcbResult: *mut DWORD,
        dwFlags: ULONG
    ) -> SECURITY_STATUS;
    pub fn NCryptCreateClaim(
        hSubjectKey: NCRYPT_KEY_HANDLE,
        hAuthorityKey: NCRYPT_KEY_HANDLE,
        dwClaimType: DWORD,
        pParameterList: *const NCryptBufferDesc,
        pbClaimBlob: PBYTE,
        cbClaimBlob: DWORD,
        pcbResult: *mut DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
    pub fn NCryptVerifyClaim(
        hSubjectKey: NCRYPT_KEY_HANDLE,
        hAuthorityKey: NCRYPT_KEY_HANDLE,
        dwClaimType: DWORD,
        pParameterList: *const NCryptBufferDesc,
        pbClaimBlob: PBYTE,
        cbClaimBlob: DWORD,
        pOutput: *mut NCryptBufferDesc,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
}

