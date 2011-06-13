#include <v8.h>
#include <node.h>
#include <stdlib.h>
#include <typeinfo>
#include <iostream>
#include <security/pam_appl.h>

struct pam_response *reply;

int null_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {

	printf("in nullconv");
	*resp = reply;
	return PAM_SUCCESS;

}

static struct pam_conv conv = { null_conv, NULL };

const char* ToCString(const v8::String::Utf8Value& value) {
	return *value ? *value : "<string conversion failed>";
}

int _pam_authenticate(char *service, char *username, char *password) {

	pam_handle_t *pamh = NULL;
	int retval = pam_start(service, username, &conv, &pamh);

	if (retval == PAM_SUCCESS) {

		reply = (struct pam_response *) malloc(sizeof(struct pam_response));
		reply[0].resp = password;
		reply[0].resp_retcode = 0;

		retval = pam_authenticate(pamh, 0);
		pam_end(pamh, PAM_SUCCESS);

	}

	return retval;

}

using namespace node;
using namespace v8;

class PAM:ObjectWrap {

private: int m_count;
public:

	 static Persistent<FunctionTemplate> s_ct;
	 static void Init(Handle<Object> target) {

		HandleScope scope;

		Local<FunctionTemplate> t = FunctionTemplate::New(New);

		s_ct = Persistent<FunctionTemplate>::New(t);
		s_ct->InstanceTemplate()->SetInternalFieldCount(1);
		s_ct->SetClassName(String::NewSymbol("PAM"));

		NODE_SET_PROTOTYPE_METHOD(s_ct, "authenticate", authenticate);
		target->Set(String::NewSymbol("PAM"), s_ct->GetFunction());

	 }

	 ~PAM() {}

	 static Handle<Value> New(const Arguments& args) {

		HandleScope scope;
		PAM* hw = new PAM();
		hw->Wrap(args.This());
		return args.This();

	 }

	 static Handle<Value> authenticate(const Arguments& args) {

		HandleScope scope;
		v8::String::Utf8Value service(args[0]);
		v8::String::Utf8Value username(args[1]);
		v8::String::Utf8Value password(args[2]);
		bool result = false;

		int retval = _pam_authenticate((char *) ToCString(service), (char *) ToCString(username), (char *) ToCString(password));

		if (retval == PAM_SUCCESS)
			result = true;

		Local<String> ret = String::New("abc");
		return ret;//scope.Close(ret);

	 }
};

Persistent<FunctionTemplate> PAM::s_ct;

extern "C" {

	static void init (Handle<Object> target) {
		PAM::Init(target);
	}

	NODE_MODULE(pam, init);
}
