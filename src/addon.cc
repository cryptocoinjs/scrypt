#include <node.h>
#include <nan.h>

extern "C" {
  #include <crypto_scrypt.h>
}

NAN_METHOD(scrypt) {
  v8::Local<v8::Object> password = info[0].As<v8::Object>();
  v8::Local<v8::Object> salt = info[1].As<v8::Object>();
  v8::Local<v8::Object> N = info[2].As<v8::Object>();
  v8::Local<v8::Object> r = info[3].As<v8::Object>();
  v8::Local<v8::Object> p = info[4].As<v8::Object>();
  v8::Local<v8::Object> length = info[5].As<v8::Object>();
  v8::Local<v8::Object> buf = node::Buffer::New(v8::Isolate::GetCurrent(), (uint64_t) length->IntegerValue()).ToLocalChecked();

  int err = crypto_scrypt(
    (const uint8_t *) node::Buffer::Data(password), node::Buffer::Length(password),
    (const uint8_t *) node::Buffer::Data(salt), node::Buffer::Length(salt),
    (uint64_t) N->IntegerValue(),
    (uint32_t) r->IntegerValue(),
    (uint32_t) p->IntegerValue(),
    (uint8_t *) node::Buffer::Data(buf), node::Buffer::Length(buf)
  );
  if (err == -1) return Nan::ThrowError("Unknow error");

  info.GetReturnValue().Set(buf);
}

void Init(Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE exports, Nan::ADDON_REGISTER_FUNCTION_ARGS_TYPE module) {
  Nan::Export(module, "exports", scrypt);
}

NODE_MODULE(scrypt, Init)
