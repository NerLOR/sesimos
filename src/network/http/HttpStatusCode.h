

#ifndef NECRONDA_HTTP_STATUSCODE
#define NECRONDA_HTTP_STATUSCODE

typedef struct {
	short code;					// The status code (e.g. 200)
	const char *type; 			// The status type type (e.g Success)
	const char *message;		// The status code message (e.g. OK)
	const char *description;	// The status code description (currently not used)
} HttpStatusCode;

HttpStatusCode getStatusCode(int statuscode);

#endif