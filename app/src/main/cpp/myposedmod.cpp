#include <jni.h>
#include <string>
#include "android/log.h"
#include "dlfcn.h"

#include "hooknative.h"

#define TAG "HookTest"

static HookFunType hook_func = nullptr;

//FILE *_Nullable fopen(const char *_Nonnull __path, const char *_Nonnull __mode);
//FILE *(*backup_fopen)(const char *filename, const char *mode);
//FILE *fake_fopen(const char *filename, const char *mode) {
//    if (strstr(filename, "banned")) return nullptr;
//    return backup_fopen(filename, mode);
//}

// void *_Nullable dlopen(const char *_Nullable __filename, int __flag);
// void *(*backup_dlopen)(const char *filename, int flag);
/*
void *fake_dlopen(const char *filename, int flag) {
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] libc dlopen called with");
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "- filename: %s", filename);
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "- flag: %d", flag);
    return backup_dlopen(filename, flag);
}
*/

// int SSL_read(SSL *ssl, void *buf, int num);
int (*backup_SSL_read)(void *ssl, void *buf, int num);

int fake_SSL_read(void *ssl, void *buf, int num) {
    int retval = backup_SSL_read(ssl, buf, num);
    const char *charBuf = static_cast<const char *>(buf);
    if (retval > 0) {
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] libssl SSL_read called with");
        // __android_log_print(ANDROID_LOG_DEBUG, TAG, "- buf:");
        __android_log_print(ANDROID_LOG_DEBUG, TAG, "%.*s", retval, charBuf);
        // __android_log_print(ANDROID_LOG_DEBUG, TAG, "- num: %d", num);
    }

    return retval;
}

// int SSL_write(SSL *ssl, const void *buf, int num);
int (*backup_SSL_write)(void *ssl, const void *buf, int num);

int fake_SSL_write(void *ssl, const void *buf, int num) {
    int retval = backup_SSL_write(ssl, buf, num);
    const char *charBuf = static_cast<const char *>(buf);
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] libssl SSL_write called with");
    // __android_log_print(ANDROID_LOG_DEBUG, TAG, "- buf:");
    __android_log_print(ANDROID_LOG_DEBUG, TAG, "%.*s", retval, charBuf);
    // __android_log_print(ANDROID_LOG_DEBUG, TAG, "- num: %d", num);

    return retval;
}

/*
jclass (*backup_FindClass)(JNIEnv *env, const char *name);
jclass fake_FindClass(JNIEnv *env, const char *name) {
    if (!strcmp(name, "dalvik/system/BaseDexClassLoader"))
        return nullptr;
    return backup_FindClass(env, name);
}
*/

void on_library_loaded(const char *name, void *handle) {
    // __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] library loaded: %s", name);
    /*
    if (strstr(name, "libssl.so")) {
        void *SSL_write = dlsym(handle, "SSL_write");
        hook_func(SSL_write, (void *) fake_SSL_write, (void **) &backup_SSL_write);
    }
    */
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
jint JNI_OnLoad(JavaVM *jvm, void *) {
    JNIEnv *env = nullptr;
    jvm->GetEnv((void **) &env, JNI_VERSION_1_6);
    // hook JNI 函数
    /*
    hook_func((void *) env->functions->FindClass, (void *) fake_FindClass,
              (void **) &backup_FindClass);
    */

    return JNI_VERSION_1_6;
}

extern "C" [[gnu::visibility("default")]] [[gnu::used]]
NativeOnModuleLoaded native_init(const NativeAPIEntries *entries) {
    // 最先被调用的位置
    // __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] native_init called");
    hook_func = entries->hook_func;

    // pid_t pid = getpid();
    // __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] Current process ID (PID): %d", pid);

    void *libssl_handle = dlopen("libssl.so", RTLD_NOW);
    if (!libssl_handle) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "\n[!] dlopen failed: %s", dlerror());
    }
    // __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] libssl_handle is at %p", libssl_handle);

    void *SSL_read = dlsym(libssl_handle, "SSL_read");
    if (!SSL_read) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "\n[!] dlsym failed: %s", dlerror());
    }
    // __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] SSL_read is at %p", SSL_read);

    void *SSL_write = dlsym(libssl_handle, "SSL_write");
    if (!SSL_write) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "\n[!] dlsym failed: %s", dlerror());
    }
    // __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] SSL_write is at %p", SSL_write);


    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (maps_file == nullptr) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "\n[!] open maps file failed");
    }
    char line[512];
    unsigned long long conscrypt_ssl_start = 0;
    unsigned long long system_ssl_start = 0;
    while (fgets(line, sizeof(line), maps_file)) {
        if (!strstr(line, "libssl.so") || !strstr(line, "r--p 00000000")) {
            continue;
        }
        // __android_log_print(ANDROID_LOG_DEBUG, TAG, "\n[*] found libssl.so: %s", line);

        if (strstr(line, "/apex/com.android.conscrypt/lib")) {
            if (sscanf(line, "%llx-", &conscrypt_ssl_start) != 1) {
                __android_log_print(ANDROID_LOG_ERROR, TAG,
                                    "can not parse conscrypt ssl start address");
            }
        }

        if (strstr(line, "/system/lib")) {
            if (sscanf(line, "%llx-", &system_ssl_start) != 1) {
                __android_log_print(ANDROID_LOG_ERROR, TAG,
                                    "can not parse system ssl start address");
            }
        }
    }
    fclose(maps_file);


    if (conscrypt_ssl_start != 0 && system_ssl_start != 0) {
        unsigned long long differce = system_ssl_start - conscrypt_ssl_start;

        void *SSL_read_conscrypt = (void *) ((char *) SSL_read - differce);
        void *SSL_write_conscrypt = (void *) ((char *) SSL_write - differce);

        hook_func(SSL_read_conscrypt, (void *) fake_SSL_read, (void **) &backup_SSL_read);
        hook_func(SSL_write_conscrypt, (void *) fake_SSL_write, (void **) &backup_SSL_write);

        dlclose(libssl_handle);
    } else {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "\n[!] hook libssl.so failed");
    }

    // system hooks
    // hook_func((void *) fopen, (void *) fake_fopen, (void **) &backup_fopen);
    // hook_func((void *) dlopen, (void *) fake_dlopen, (void **) &backup_dlopen);

    return on_library_loaded;
}