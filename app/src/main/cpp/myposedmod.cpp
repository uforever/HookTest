#include <jni.h>
#include <string>
#include "android/log.h"
#include "dlfcn.h"

#include "hooknative.h"

#define TAG "HookTest"

static HookFunType hook_func = nullptr;

int (*backup)();

int (*backup_SSL_write)(void *ssl, const void *buf, int num);

bool has_ending(std::string const &fullString, std::string const &ending) {
    if (fullString.length() >= ending.length()) {
        return (0 ==
                fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
    } else {
        return false;
    }
}

int fake() {
    return backup() + 1;
}

int fake_SSL_write(void *ssl, const void *buf, int num) {
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] libssl SSL_write called with");

    return backup_SSL_write(ssl, buf, num);
}

FILE *(*backup_fopen)(const char *filename, const char *mode);

FILE *fake_fopen(const char *filename, const char *mode) {
    if (strstr(filename, "banned")) return nullptr;
    return backup_fopen(filename, mode);
}

jclass (*backup_FindClass)(JNIEnv *env, const char *name);

jclass fake_FindClass(JNIEnv *env, const char *name) {
    if (!strcmp(name, "dalvik/system/BaseDexClassLoader"))
        return nullptr;
    return backup_FindClass(env, name);
}

void on_library_loaded(const char *name, void *handle) {
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] on_library_loaded called with %s", name);
    if (has_ending(std::string(name), "libssl.so")) {
        void *SSL_write = dlsym(handle, "SSL_write");
        hook_func(SSL_write, (void *) fake_SSL_write, (void **) &backup_SSL_write);
    }

    return;
    // hooks on `libtarget.so`
    // if (std::string(name).ends_with("libtarget.so")) {
    /*
    if (has_ending(std::string(name), "libtarget.so")) {
        void *target = dlsym(handle, "target_fun");
        hook_func(target, (void *) fake, (void **) &backup);
    }
    */
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
jint JNI_OnLoad(JavaVM *jvm, void *) {
    JNIEnv *env = nullptr;
    jvm->GetEnv((void **) &env, JNI_VERSION_1_6);
    /*
    hook_func((void *) env->functions->FindClass, (void *) fake_FindClass,
              (void **) &backup_FindClass);
    */
    return JNI_VERSION_1_6;
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] libssl SSL_write called with");
    hook_func = entries->hook_func;
    // system hooks
    // hook_func((void *) fopen, (void *) fake_fopen, (void **) &backup_fopen);
    return on_library_loaded;
}