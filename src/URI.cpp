
#include "URI.h"
#include "necronda-server.h"
#include <utility>
#include <sys/stat.h>

using namespace std;

string getExtension(string path) {
	long pos = path.find_last_of('.');
	if (pos == string::npos) {
		return "";
	}
	return path.substr(pos + 1, path.length() - pos);
}

string getFilename(string path) {
	long pos = path.find_last_of('/');
	if (pos == string::npos) {
		return "";
	}
	return path.substr(pos + 1, path.length() - pos);
}

bool isDirectory(string path) {
	struct stat statbuf;
	return stat(path.c_str(), &statbuf) == 0 && S_ISDIR(statbuf.st_mode) != 0;
}

bool isFile(string path) {
	struct stat statbuf;
	return stat(path.c_str(), &statbuf) == 0 && S_ISDIR(statbuf.st_mode) == 0;
}

bool fileExists(string path) {
	struct stat statbuf;
	return stat(path.c_str(), &statbuf) == 0;
}

URI::URI(string webroot, string reqpath) {
	unsigned long pos = reqpath.find('?');
	if (pos != string::npos) {
		queryinit = true;
		query = reqpath.substr(pos + 1, reqpath.length() - pos);
		reqpath.erase(pos, reqpath.length() - pos);
	} else {
		query = "";
		queryinit = false;
	}
	if (webroot[webroot.length() - 1] == '/') {
		webroot.erase(webroot.length() - 1);
	}
	reqpath = url_decode(reqpath);
	if (reqpath.find("/../") != string::npos) {
		throw (char *) "Invalid path";
	}
	if (reqpath[0] != '/') {
		reqpath = '/' + reqpath;
	}
	this->webroot = webroot;
	this->reqpath = reqpath;

	info = "";
	relpath = reqpath;

	while (!fileExists(webroot + relpath) && !fileExists(webroot + relpath + ".php") && !fileExists(webroot + relpath + ".html")) {
		long slash = relpath.find_last_of('/');
		if (slash == string::npos) {
			break;
		}
		info = relpath.substr(slash) + info;
		relpath.erase(slash);
	}

	if (!info.empty() && isDirectory(webroot + relpath)) {
		relpath.append("/");
	}

	string abs = relpath;
	if (fileExists(webroot + abs)) {
		string ext = getExtension(abs);
		if (ext == "php" || ext == "html") {
			abs.erase(abs.length() - ext.length() - 1, abs.length());
		}
	}

	string fname = getFilename(abs);
	if (fname == "index") {
		abs.erase(abs.length() - fname.length() - 1, abs.length());
	}

	this->filepath = webroot + relpath;

	if (isDirectory(webroot + abs)) {
		if (abs[abs.length() - 1] != '/') {
			abs += "/";
		}
		this->relpath = abs;
		abs += "index";
		if (fileExists(webroot + abs + ".php")) {
			this->filepath = webroot + abs + ".php";
		} else if (fileExists(webroot + abs + ".html")) {
			this->filepath = webroot + abs + ".html";
		}
	} else {
		if (abs[abs.length() - 1] == '/') {
			abs.erase(abs.length() - 1, abs.length() - 1);
		}
		this->relpath = abs;
		if (fileExists(webroot + abs + ".php")) {
			this->filepath = webroot + abs + ".php";
		} else if (fileExists(webroot + abs + ".html")) {
			this->filepath = webroot + abs + ".html";
		}
	}

	if (isStatic() && !info.empty()) {
		if (relpath[relpath.length() - 1] == '/') {
			relpath.erase(relpath.length() - 1);
		}
		newpath = relpath + info;
		filepath = "";
	} else if (relpath != reqpath) {
		if (!info.empty()) {
			info.erase(0,1);
		}
		newpath = relpath + info;
	} else {
		newpath = "";
	}

}

string URI::getWebRoot() {
	return webroot;
}

string URI::getRelativePath() {
	return relpath;
}

string URI::getAbsolutePath() {
	return webroot + relpath;
}

string URI::getFilePath() {
	return filepath;
}

string URI::getRelativeFilePath() {
	string str = getFilePath();
	long len = getWebRoot().length();
	return str.substr(len, str.length() - len);
}

string URI::getNewPath() {
	if (isStatic()) {
		if (hasQuery()) {
			return getRelativePath();
		}
	}
	if (!newpath.empty() && newpath != reqpath) {
		return url_encode(newpath) + (queryinit? "?" + query : "");
	} else {
		return "";
	}
}

FILE *URI::openFile() {
	return fopen64(getFilePath().c_str(), "rb");
}

string URI::getFilePathInfo() {
	return info; //getAbsolutePath().erase(getFilePath().length(), getAbsolutePath().length());
}

string URI::getFileType() {
	return getMimeType(getFilePath());
}

bool URI::isStatic() {
	return getExtension(filepath) != "php";
}

string URI::getQuery() {
	return query;
}

bool URI::hasQuery() {
	return queryinit;
}

