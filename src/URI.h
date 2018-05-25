
#include <iostream>

#ifndef NECRONDA_PATH
#define NECRONDA_PATH

using namespace std;

class URI {
private:
	string webroot;
	string reqpath;
	string relpath;
	string query;
	string filepath;
	bool queryinit;

public:
	URI(string webroot, string reqpath);

	string getWebRoot();

	string getRelativePath();

	string getAbsolutePath();

	string getFilePath();

	string getRelativeFilePath();

	string getNewPath();

	FILE *openFile();

	string getFilePathInfo();

	string getFileType();

	bool isStatic();

	string getQuery();

	bool hasQuery();

};

#endif
