
#include "Path.h"
#include "necronda-server.h"
#include <utility>

using namespace std;

Path::Path(string webroot, string reqpath) {
	unsigned long pos = reqpath.find('?');
	if (pos != string::npos) {
		query = reqpath.substr(pos + 1, reqpath.length() - pos);
		reqpath.erase(pos + 1, reqpath.length() - pos);
	}
	if (webroot[webroot.length() - 1] == '/') {
		webroot.erase(webroot.length() - 1);
	}
	if (reqpath.find("/../") != string::npos) {
		throw (char *) "Invalid path";
	}
	if (reqpath[0] != '/') {
		reqpath = '/' + reqpath;
	}
	this->webroot = webroot;
	this->relpath = reqpath;
}

string Path::getWebRoot() {
	return webroot;
}

string Path::getRelativePath() {
	return relpath;
}

string Path::getAbsolutePath() {
	return webroot + relpath;
}

string Path::getFilePath() {
	string abs = webroot;
	// TODO
	return getAbsolutePath();
}

string Path::getRelativeFilePath() {
	string rel = getRelativePath();
	// TODO
}

string Path::getNewPath() {
	string rel = getRelativeFilePath();
	// TODO
	return nullptr;
}

FILE *Path::openFile() {
	return fopen64(getFilePath().c_str(), "r");
}

string Path::getFilePathInfo() {
	return getAbsolutePath().erase(getFilePath().length(), getAbsolutePath().length());
}

string Path::getFileType() {
	return getMimeType(getFilePath());
}

bool Path::isStatic() {
	return true;
}

