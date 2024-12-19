#include <iostream>
#include "ULockFileClass.h"

using namespace std;

string getSIDbyUsername(string username) {
    DWORD sidSize = 0;
    DWORD domainSize = 0;
    SID_NAME_USE sidType;
    LPSTR sidString = NULL;

    LookupAccountNameA(NULL, username.c_str(), NULL, &sidSize, NULL, &domainSize, &sidType);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        cerr << "Failed to get buffer sizes for SID." << endl;
        return "";
    }

    PSID sid = (PSID)malloc(sidSize);
    char* domainName = (char*)malloc(domainSize);

    if (!sid || !domainName) {
        cerr << "Memory allocation failed." << endl;
        if (sid) free(sid);
        if (domainName) free(domainName);
        return "";
    }

    if (!LookupAccountNameA(NULL, username.c_str(), sid, &sidSize, domainName, &domainSize, &sidType)) {
        cerr << "Failed to look up account name." << endl;
        free(sid);
        free(domainName);
        return "";
    }


    if (!ConvertSidToStringSidA(sid, &sidString)) {
        cerr << "Failed to convert SID to string." << endl;
        free(sid);
        free(domainName);
        return "";
    }

    string sidResult = sidString;

    LocalFree(sidString);
    free(sid);
    free(domainName);
    return sidResult;
}

string getGSIDbyUsername(string username) {
	DWORD sidSize = 0;
	DWORD domainSize = 0;
	SID_NAME_USE sidType;
	LPSTR sidString = NULL;

	LookupAccountNameA(NULL, username.c_str(), NULL, &sidSize, NULL, &domainSize, &sidType);

	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		cerr << "Failed to get buffer sizes for SID." << endl;
		return "";
	}

	PSID sid = (PSID)malloc(sidSize);
	char* domainName = (char*)malloc(domainSize);

	if (!sid || !domainName) {
		cerr << "Memory allocation failed." << endl;
		if (sid) free(sid);
		if (domainName) free(domainName);
		return "";
	}

	if (!LookupAccountNameA(NULL, username.c_str(), sid, &sidSize, domainName, &domainSize, &sidType)) {
		cerr << "Failed to look up account name." << endl;
		free(sid);
		free(domainName);
		return "";
	}


	if (!ConvertSidToStringSidA(sid, &sidString)) {
		cerr << "Failed to convert SID to string." << endl;
		free(sid);
		free(domainName);
		return "";
	}

	string sidResult = sidString;

	LocalFree(sidString);
	free(sid);
	free(domainName);
	return sidResult;
}


int main()
{
    string filePath = "C:\\Users\\s12\\Documents\\si.txt";
    ULockFile locker;
    string userSID = getSIDbyUsername("s12");

    if (locker.DenyUserAccess(filePath, userSID)) {
        cout << "Blocked Access Completed" << endl;
    }
    else {
        cout << "Error Blocking File for user" << endl;
    }

    string gSID = getGSIDbyUsername("s12");
    cout << "GSID" << gSID << endl;
	if (locker.DenyUserGroupAccess(filePath, gSID)) {
		cout << "Blocked Access Completed" << endl;
	}
	else {
		cout << "Error Blocking File for group" << endl;
	}

    bool resuklt = locker.MarkFileAsSystemHidden(filePath);
	if (resuklt) {
		cout << "File Marked As System" << endl;
	}
	else {
		cout << "Error Marking File As System" << endl;
	}


    return 0;
}