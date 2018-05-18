
#include <iostream>

#ifndef NECRONDA_PATH
#define NECRONDA_PATH

using namespace std;

class Path {
private:
	string webroot;
	string relpath;
	string query;

public:
	Path(string webroot, string reqpath);

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

};

#endif
