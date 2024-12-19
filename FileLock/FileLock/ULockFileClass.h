#include <Windows.h>
#include <iostream>
#include <AclAPI.h>
#include <sddl.h>

using namespace std;

class ULockFile {
public:
    // Deny user access with DACL
    bool DenyUserAccess(const string& filePath, const string& userSID) {
        PSID pSid = NULL;
        EXPLICIT_ACCESS ea = {};
        PACL pNewAcl = NULL;

        // Convert the SID string to a PSID
        if (!ConvertStringSidToSidA(userSID.c_str(), &pSid)) {
            cerr << "Failed to convert user SID." << endl;
            return false;
        }

        // Set the access entry to deny all permissions
        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode = DENY_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
        ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSid);

        if (SetEntriesInAcl(1, &ea, NULL, &pNewAcl) != ERROR_SUCCESS) {
            cerr << "Failed to set entries in ACL." << endl;
            LocalFree(pSid);
            return false;
        }

        if (SetNamedSecurityInfoA((LPSTR)filePath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewAcl, NULL) != ERROR_SUCCESS) {
            cerr << "Failed to set security info." << endl;
            LocalFree(pNewAcl);
            LocalFree(pSid);
            return false;
        }

        LocalFree(pNewAcl);
        LocalFree(pSid);
        return true;
    }

    // Deny user group access
    bool DenyUserGroupAccess(const string& filePath, const string& groupSID) {
        PSID pSid = NULL;
        EXPLICIT_ACCESS ea = {};
        PACL pNewAcl = NULL;

        if (!ConvertStringSidToSidA(groupSID.c_str(), &pSid)) {
            cerr << "Failed to convert group SID." << endl;
            return false;
        }

        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode = DENY_ACCESS;
        ea.grfInheritance = NO_INHERITANCE;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea.Trustee.ptstrName = reinterpret_cast<LPWSTR>(pSid);

        if (SetEntriesInAcl(1, &ea, NULL, &pNewAcl) != ERROR_SUCCESS) {
            cerr << "Failed to set entries in ACL." << endl;
            LocalFree(pSid);
            return false;
        }

        if (SetNamedSecurityInfoA((LPSTR)filePath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewAcl, NULL) != ERROR_SUCCESS) {
            cerr << "Failed to set security info." << endl;
            LocalFree(pNewAcl);
            LocalFree(pSid);
            return false;
        }

        LocalFree(pNewAcl);
        LocalFree(pSid);
        return true;
    }

    // Mark file as System file with FILE_ATTRIBUTE_SYSTEM
    bool MarkFileAsSystemHidden(const string& filePath) {
        DWORD attributes = GetFileAttributesA(filePath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            cerr << "Failed to get file attributes." << endl;
            return false;
        }

        if (!SetFileAttributesA(filePath.c_str(), attributes | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)) {
            cerr << "Failed to set file as system." << endl;
            return false;
        }

        return true;
    }

 //   // Lock file with LockFileEx, Only lock the locker process
 //   bool LockFile(const string& filePath) {
 //       HANDLE hFile = CreateFileA(
 //           filePath.c_str(),
 //           GENERIC_READ | GENERIC_WRITE,
 //           0,
 //           NULL,
 //           OPEN_EXISTING,
 //           FILE_ATTRIBUTE_NORMAL,
 //           NULL
 //       );

 //       if (hFile == INVALID_HANDLE_VALUE) {
 //           cerr << "Failed to open file for locking." << endl;
 //           return false;
 //       }

 //       OVERLAPPED overlapped = {};
 //       if (!LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapped)) {
 //           cerr << "Failed to lock file." << endl;
 //           CloseHandle(hFile);
 //           return false;
 //       }

 //       cout << "File locked successfully." << endl;
 //       // Keep the file locked as long as needed

 //       // Unlock the file and close handle (Optional in real-world usage)
 //       //UnlockFileEx(hFile, 0, MAXDWORD, MAXDWORD, &overlapped);
 //       CloseHandle(hFile);

 //       return true;
 //   }

 //   bool UnlockFile(const string& filePath) {
	//	HANDLE hFile = CreateFileA(
	//		filePath.c_str(),
	//		GENERIC_READ | GENERIC_WRITE,
	//		0,
	//		NULL,
	//		OPEN_EXISTING,
	//		FILE_ATTRIBUTE_NORMAL,
	//		NULL
	//	);

	//	if (hFile == INVALID_HANDLE_VALUE) {
	//		cerr << "Failed to open file for unlocking." << endl;
	//		return false;
	//	}

	//	OVERLAPPED overlapped = {};
	//	if (!UnlockFileEx(hFile, 0, MAXDWORD, MAXDWORD, &overlapped)) {
	//		cerr << "Failed to unlock file." << endl;
	//		CloseHandle(hFile);
	//		return false;
	//	}

	//	cout << "File unlocked successfully." << endl;

	//	CloseHandle(hFile);
	//	return true;
	//}
    


};

