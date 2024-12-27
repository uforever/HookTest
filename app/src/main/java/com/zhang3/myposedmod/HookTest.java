package com.zhang3.myposedmod;

import android.app.Application;
import android.content.Context;
import android.util.Base64;
import android.util.Log;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;


public class HookTest implements IXposedHookLoadPackage {

    private static final String TAG = "HookTest";

    private static ClassLoader classLoader;
    private boolean alreadyHooked = false;

    public static String toHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        // 过滤不必要的应用
        if (lpparam.packageName.startsWith("com.zhang3.")) return;

        try {
            System.loadLibrary("myposedmod");
        } catch (Throwable e) {
            Log.e(TAG, "load Native hook Library failed", e);
        }

        // 执行Hook
        hookJava(lpparam);
    }

    private void hookJava(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (alreadyHooked) return;
        alreadyHooked = true;

        classLoader = lpparam.classLoader;
        // 带壳app切换ClassLoader
        XposedHelpers.findAndHookMethod(Application.class, "attach", Context.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Context context = (Context) param.args[0];
                classLoader = context.getClassLoader();
            }
        });

        // Class<?> keyGenerator = XposedHelpers.findClass("javax.crypto.KeyGenerator", classLoader);

        // 这两个密钥生成类没必要hook
        /*
        XposedHelpers.findAndHookMethod(KeyGenerator.class, "generateKey", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                SecretKey secretKey = (SecretKey) param.getResult();
                Log.i(TAG, "\n[*] javax.crypto.KeyGenerator.generateKey() onLeave");
                if (secretKey != null) {
                    byte[] keyData = secretKey.getEncoded();
                    Log.i(TAG, "- algorithm: " + secretKey.getAlgorithm());
                    Log.i(TAG, "- format: " + secretKey.getFormat());
                    Log.i(TAG, "- key(hex): " + toHexString(keyData));
                    Log.i(TAG, "- key(base64): " + Base64.encodeToString(keyData, Base64.NO_WRAP));
                }
            }
        });
        */
        
        /*
        XposedHelpers.findAndHookMethod(KeyPairGenerator.class, "generateKeyPair", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                KeyPair keyPair = (KeyPair) param.getResult();
                KeyPairGenerator thisObj = (KeyPairGenerator) param.thisObject;
                Log.i(TAG, "\n[*] java.security.KeyPairGenerator.generateKeyPair() onLeave");
                Log.i(TAG, "- algorithm: " + thisObj.getAlgorithm());
                if (keyPair != null) {
                    PublicKey publicKey = keyPair.getPublic();
                    PrivateKey privateKey = keyPair.getPrivate();
                    if (publicKey != null) {
                        byte[] publicKeyData = publicKey.getEncoded();
                        Log.i(TAG, "- public key(hex): " + toHexString(publicKeyData));
                        Log.i(TAG, "- public key(base64): " + Base64.encodeToString(publicKeyData, Base64.NO_WRAP));
                    }
                    if (privateKey != null) {
                        byte[] privateKeyData = privateKey.getEncoded();
                        Log.i(TAG, "- private key(hex): " + toHexString(privateKeyData));
                        Log.i(TAG, "- private key(base64): " + Base64.encodeToString(privateKeyData, Base64.NO_WRAP));
                    }
                }
            }
        });
        */


        XposedHelpers.findAndHookMethod(MessageDigest.class, "update", byte.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                MessageDigest thisObj = (MessageDigest) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                byte b = (byte) param.args[0];
                Log.i(TAG, "\n[*] java.security.MessageDigest.update() onEnter");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- input(hex): " + String.format("0x%02x", b));
            }
        });

        XposedHelpers.findAndHookMethod(MessageDigest.class, "update", byte[].class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                MessageDigest thisObj = (MessageDigest) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                byte[] input = (byte[]) param.args[0];
                String inputBase64 = Base64.encodeToString(input, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.MessageDigest.update() onEnter");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- input(raw): " + new String(input));
                Log.i(TAG, "- input(base64): " + inputBase64);
            }
        });

        XposedHelpers.findAndHookMethod(MessageDigest.class, "update", byte[].class, int.class, int.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                MessageDigest thisObj = (MessageDigest) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                byte[] input = (byte[]) param.args[0];
                int offset = (int) param.args[1];
                int length = (int) param.args[2];
                String inputBase64 = Base64.encodeToString(input, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.MessageDigest.update() onEnter");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- input(raw): " + new String(input));
                Log.i(TAG, "- input(base64): " + inputBase64);
                Log.i(TAG, "- offset: " + offset);
                Log.i(TAG, "- length: " + length);
            }
        });

        XposedHelpers.findAndHookMethod(MessageDigest.class, "update", ByteBuffer.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                MessageDigest thisObj = (MessageDigest) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                ByteBuffer inputBuffer = (ByteBuffer) param.args[0];
                byte[] input = inputBuffer.array();
                String inputBase64 = Base64.encodeToString(input, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.MessageDigest.update() onEnter");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- input(raw): " + new String(input));
                Log.i(TAG, "- input(base64): " + inputBase64);
            }
        });

        XposedHelpers.findAndHookMethod(MessageDigest.class, "digest", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                MessageDigest thisObj = (MessageDigest) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                byte[] digest = (byte[]) param.getResult();
                String digestBase64 = Base64.encodeToString(digest, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.MessageDigest.digest() onLeave");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- output(hex): " + toHexString(digest));
                Log.i(TAG, "- output(base64): " + digestBase64);
            }
        });

        XposedHelpers.findAndHookMethod(MessageDigest.class, "digest", byte[].class, int.class, int.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                MessageDigest thisObj = (MessageDigest) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                byte[] output = (byte[]) param.args[0];
                int offset = (int) param.args[1];
                int length = (int) param.args[2];
                String digestBase64 = Base64.encodeToString(output, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.MessageDigest.digest() onLeave");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- output(hex): " + toHexString(output));
                Log.i(TAG, "- output(base64): " + digestBase64);
                Log.i(TAG, "- offset: " + offset);
                Log.i(TAG, "- length: " + length);
            }
        });

        // 批量hook
        XposedBridge.hookAllMethods(Signature.class, "initSign", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                PrivateKey privateKey = (PrivateKey) param.args[0];
                String privateKeyAlgorithm = privateKey.getAlgorithm();
                String privateKeyFormat = privateKey.getFormat();
                byte[] privateKeyBytes = privateKey.getEncoded();
                String privateKeyBase64 = Base64.encodeToString(privateKeyBytes, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.Signature.initSign() onEnter");
                Log.i(TAG, "- algorithm: " + privateKeyAlgorithm);
                Log.i(TAG, "- key format: " + privateKeyFormat);
                Log.i(TAG, "- private key(hex): " + toHexString(privateKeyBytes));
                Log.i(TAG, "- private key(base64): " + privateKeyBase64);
            }
        });

        XposedHelpers.findAndHookMethod(Signature.class, "sign", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                byte[] outputBytes = (byte[]) param.getResult();
                String outputBase64 = Base64.encodeToString(outputBytes, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.Signature.sign() onLeave");
                Log.i(TAG, "- output(hex): " + toHexString(outputBytes));
                Log.i(TAG, "- output(base64): " + outputBase64);
            }
        });

        XposedHelpers.findAndHookMethod(Signature.class, "sign", byte[].class, int.class, int.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                byte[] outputBytes = (byte[]) param.args[0];
                int offset = (int) param.args[1];
                int length = (int) param.args[2];
                String outputBase64 = Base64.encodeToString(outputBytes, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.Signature.sign() onLeave");
                Log.i(TAG, "- output(hex): " + toHexString(outputBytes));
                Log.i(TAG, "- output(base64): " + outputBase64);
                Log.i(TAG, "- offset: " + offset);
                Log.i(TAG, "- length: " + length);
            }
        });

        XposedHelpers.findAndHookMethod(Signature.class, "initVerify", PublicKey.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                PublicKey publicKey = (PublicKey) param.args[0];
                String publicKeyAlgorithm = publicKey.getAlgorithm();
                String publicKeyFormat = publicKey.getFormat();
                byte[] publicKeyBytes = publicKey.getEncoded();
                String publicKeyBase64 = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.Signature.initVerify() onEnter");
                Log.i(TAG, "- algorithm: " + publicKeyAlgorithm);
                Log.i(TAG, "- key format: " + publicKeyFormat);
                Log.i(TAG, "- public key(hex): " + toHexString(publicKeyBytes));
                Log.i(TAG, "- public key(base64): " + publicKeyBase64);
            }
        });

        XposedHelpers.findAndHookMethod(Signature.class, "initVerify", Certificate.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                Certificate certificate = (Certificate) param.args[0];
                byte[] certificateBytes = certificate.getEncoded();
                String certificateBase64 = Base64.encodeToString(certificateBytes, Base64.NO_WRAP);

                PublicKey publicKey = certificate.getPublicKey();
                String publicKeyAlgorithm = publicKey.getAlgorithm();
                String publicKeyFormat = publicKey.getFormat();
                byte[] publicKeyBytes = publicKey.getEncoded();
                String publicKeyBase64 = Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.Signature.initVerify() onEnter");
                Log.i(TAG, "- algorithm: " + publicKeyAlgorithm);
                Log.i(TAG, "- certificate(hex): " + toHexString(certificateBytes));
                Log.i(TAG, "- certificate(base64): " + certificateBase64);
                Log.i(TAG, "- key format: " + publicKeyFormat);
                Log.i(TAG, "- public key(hex): " + toHexString(publicKeyBytes));
                Log.i(TAG, "- public key(base64): " + publicKeyBase64);
            }
        });

        XposedHelpers.findAndHookMethod(Signature.class, "verify", byte[].class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                byte[] signBytes = (byte[]) param.args[0];
                String signBase64 = Base64.encodeToString(signBytes, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.Signature.verify() onEnter");
                Log.i(TAG, "- sign(hex): " + toHexString(signBytes));
                Log.i(TAG, "- sign(base64): " + signBase64);
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                boolean result = (boolean) param.getResult();
                Log.i(TAG, "\n[*] java.security.Signature.verify() onLeave");
                Log.i(TAG, "- result: " + result);
            }
        });

        XposedHelpers.findAndHookMethod(Signature.class, "verify", byte[].class, int.class, int.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                byte[] signBytes = (byte[]) param.args[0];
                int offset = (int) param.args[1];
                int length = (int) param.args[2];
                String signBase64 = Base64.encodeToString(signBytes, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.Signature.verify() onEnter");
                Log.i(TAG, "- sign(hex): " + toHexString(signBytes));
                Log.i(TAG, "- sign(base64): " + signBase64);
                Log.i(TAG, "- offset: " + offset);
                Log.i(TAG, "- length: " + length);
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                boolean result = (boolean) param.getResult();
                Log.i(TAG, "\n[*] java.security.Signature.verify() onLeave");
                Log.i(TAG, "- result: " + result);
            }
        });

        XposedHelpers.findAndHookMethod(Signature.class, "update", byte.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                Signature thisObj = (Signature) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                byte b = (byte) param.args[0];
                Log.i(TAG, "\n[*] java.security.Signature.update() onEnter");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- input(hex): " + String.format("0x%02x", b));
            }
        });

        XposedHelpers.findAndHookMethod(Signature.class, "update", byte[].class, int.class, int.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                Signature thisObj = (Signature) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                byte[] input = (byte[]) param.args[0];
                int offset = (int) param.args[1];
                int length = (int) param.args[2];
                String inputBase64 = Base64.encodeToString(input, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.Signature.update() onEnter");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- input(raw): " + new String(input));
                Log.i(TAG, "- input(base64): " + inputBase64);
                Log.i(TAG, "- offset: " + offset);
                Log.i(TAG, "- length: " + length);
            }
        });

        XposedHelpers.findAndHookMethod(Signature.class, "update", ByteBuffer.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                Signature thisObj = (Signature) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                ByteBuffer inputBuffer = (ByteBuffer) param.args[0];
                byte[] input = inputBuffer.array();
                String inputBase64 = Base64.encodeToString(input, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] java.security.Signature.update() onEnter");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- input(raw): " + new String(input));
                Log.i(TAG, "- input(base64): " + inputBase64);
            }
        });

//        Class<?> cipher = XposedHelpers.findClass("javax.crypto.Cipher", classLoader);

        // 批量hook
        XposedBridge.hookAllMethods(Cipher.class, "chooseProvider", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                int opmode = (int) param.args[1];
                String opmodeString = (String) XposedHelpers.callMethod(param.thisObject, "getOpmodeString", opmode);
                String algorithm = (String) XposedHelpers.callMethod(param.thisObject, "getAlgorithm");
                Key key = (Key) param.args[2];
                byte[] keyBytes = key.getEncoded();
                String keyBase64 = Base64.encodeToString(keyBytes, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.init() onEnter");
                Log.i(TAG, "- op mode: " + opmodeString);
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- key(raw): " + new String(keyBytes));
                Log.i(TAG, "- key(base64): " + keyBase64);

                if (param.args[3] instanceof IvParameterSpec) {
                    byte[] ivBytes = (byte[]) XposedHelpers.callMethod(param.args[3], "getIV");
                    String ivBase64 = Base64.encodeToString(ivBytes, Base64.NO_WRAP);
                    Log.i(TAG, "- iv(raw): " + new String(ivBytes));
                    Log.i(TAG, "- iv(base64): " + ivBase64);
                } else {
                    Log.i(TAG, "- iv: null");
                }
            }
        });


        XposedHelpers.findAndHookMethod(Cipher.class, "doFinal", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                byte[] result = (byte[]) param.getResult();
                String resultBase64 = Base64.encodeToString(result, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.doFinal() onLeave");
                Log.i(TAG, "- output(raw): " + new String(result));
                Log.i(TAG, "- output(base64): " + resultBase64);
            }
        });

        XposedHelpers.findAndHookMethod(Cipher.class, "doFinal", byte[].class, int.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                byte[] output = (byte[]) param.args[0];
                int offset = (int) param.args[1];
                String resultBase64 = Base64.encodeToString(output, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.doFinal() onLeave");
                Log.i(TAG, "- output(raw): " + new String(output));
                Log.i(TAG, "- output(base64): " + resultBase64);
                Log.i(TAG, "- offset: " + offset);
            }
        });

        XposedHelpers.findAndHookMethod(Cipher.class, "doFinal", byte[].class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                byte[] data = (byte[]) param.args[0];
                String dataBase64 = Base64.encodeToString(data, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.doFinal() onEnter");
                Log.i(TAG, "- input(raw): " + new String(data));
                Log.i(TAG, "- input(base64): " + dataBase64);
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                byte[] result = (byte[]) param.getResult();
                String resultBase64 = Base64.encodeToString(result, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.doFinal() onLeave");
                Log.i(TAG, "- output(raw): " + new String(result));
                Log.i(TAG, "- output(base64): " + resultBase64);
            }
        });

        XposedHelpers.findAndHookMethod(Cipher.class, "doFinal", byte[].class, int.class, int.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                byte[] data = (byte[]) param.args[0];
                int offset = (int) param.args[1];
                int length = (int) param.args[2];
                String dataBase64 = Base64.encodeToString(data, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.doFinal() onEnter");
                Log.i(TAG, "- input(raw): " + new String(data));
                Log.i(TAG, "- input(base64): " + dataBase64);
                Log.i(TAG, "- offset: " + offset);
                Log.i(TAG, "- length: " + length);
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                byte[] result = (byte[]) param.getResult();
                String resultBase64 = Base64.encodeToString(result, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.doFinal() onLeave");
                Log.i(TAG, "- output(raw): " + new String(result));
                Log.i(TAG, "- output(base64): " + resultBase64);
            }
        });

        XposedHelpers.findAndHookMethod(Cipher.class, "doFinal", byte[].class, int.class, int.class, byte[].class, new XC_MethodHook() {
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                byte[] data = (byte[]) param.args[0];
                int offset = (int) param.args[1];
                int length = (int) param.args[2];
                String dataBase64 = Base64.encodeToString(data, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.doFinal() onEnter");
                Log.i(TAG, "- input(raw): " + new String(data));
                Log.i(TAG, "- input(base64): " + dataBase64);
                Log.i(TAG, "- offset: " + offset);
                Log.i(TAG, "- length: " + length);
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                byte[] output = (byte[]) param.args[3];
                String resultBase64 = Base64.encodeToString(output, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.doFinal() onLeave");
                Log.i(TAG, "- output(raw): " + new String(output));
                Log.i(TAG, "- output(base64): " + resultBase64);
            }
        });

        XposedHelpers.findAndHookMethod(Cipher.class, "doFinal", byte[].class, int.class, int.class, byte[].class, int.class, new XC_MethodHook() {
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                byte[] data = (byte[]) param.args[0];
                int offset = (int) param.args[1];
                int length = (int) param.args[2];
                String dataBase64 = Base64.encodeToString(data, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.doFinal() onEnter");
                Log.i(TAG, "- input(raw): " + new String(data));
                Log.i(TAG, "- input(base64): " + dataBase64);
                Log.i(TAG, "- offset: " + offset);
                Log.i(TAG, "- length: " + length);
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                byte[] output = (byte[]) param.args[3];
                int offset = (int) param.args[4];
                String resultBase64 = Base64.encodeToString(output, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.doFinal() onLeave");
                Log.i(TAG, "- output(raw): " + new String(output));
                Log.i(TAG, "- output(base64): " + resultBase64);
                Log.i(TAG, "- offset: " + offset);
            }
        });

        XposedHelpers.findAndHookMethod(Cipher.class, "doFinal", ByteBuffer.class, ByteBuffer.class, new XC_MethodHook() {
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                ByteBuffer inputBuffer = (ByteBuffer) param.args[0];
                byte[] input = inputBuffer.array();
                String dataBase64 = Base64.encodeToString(input, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.doFinal() onEnter");
                Log.i(TAG, "- input(raw): " + new String(input));
                Log.i(TAG, "- input(base64): " + dataBase64);
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                ByteBuffer inputBuffer = (ByteBuffer) param.args[0];
                byte[] output = inputBuffer.array();
                String resultBase64 = Base64.encodeToString(output, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Cipher.doFinal() onLeave");
                Log.i(TAG, "- output(raw): " + new String(output));
                Log.i(TAG, "- output(base64): " + resultBase64);
            }
        });


        XposedBridge.hookAllMethods(Mac.class, "init", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                Key key = (Key) param.args[0];
                byte[] keyBytes = key.getEncoded();
                String keyBase64 = Base64.encodeToString(keyBytes, Base64.NO_WRAP);
                Mac thisObj = (Mac) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                Log.i(TAG, "\n[*] javax.crypto.Mac.init() onEnter");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- key(hex): " + toHexString(keyBytes));
                Log.i(TAG, "- key(base64): " + keyBase64);
            }
        });

        XposedHelpers.findAndHookMethod(Mac.class, "update", byte.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                Mac thisObj = (Mac) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                byte b = (byte) param.args[0];
                Log.i(TAG, "\n[*] javax.crypto.Mac.update() onEnter");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- input(hex): " + String.format("0x%02x", b));
            }
        });

        XposedHelpers.findAndHookMethod(Mac.class, "update", byte[].class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                Mac thisObj = (Mac) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                byte[] input = (byte[]) param.args[0];
                String inputBase64 = Base64.encodeToString(input, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Mac.update() onEnter");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- input(raw): " + new String(input));
                Log.i(TAG, "- input(base64): " + inputBase64);
            }
        });

        XposedHelpers.findAndHookMethod(Mac.class, "update", byte[].class, int.class, int.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                Mac thisObj = (Mac) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                byte[] input = (byte[]) param.args[0];
                int offset = (int) param.args[1];
                int length = (int) param.args[2];
                String inputBase64 = Base64.encodeToString(input, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Mac.update() onEnter");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- input(raw): " + new String(input));
                Log.i(TAG, "- input(base64): " + inputBase64);
                Log.i(TAG, "- offset: " + offset);
                Log.i(TAG, "- length: " + length);
            }
        });

        XposedHelpers.findAndHookMethod(Mac.class, "update", ByteBuffer.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                Mac thisObj = (Mac) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                ByteBuffer inputBuffer = (ByteBuffer) param.args[0];
                byte[] input = inputBuffer.array();
                String inputBase64 = Base64.encodeToString(input, Base64.NO_WRAP);
                Log.i(TAG, "\n[*] javax.crypto.Mac.update() onEnter");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- input(raw): " + new String(input));
                Log.i(TAG, "- input(base64): " + inputBase64);
            }
        });

        XposedHelpers.findAndHookMethod(Mac.class, "doFinal", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                byte[] output = (byte[]) param.getResult();
                Mac thisObj = (Mac) param.thisObject;
                String algorithm = thisObj.getAlgorithm();
                String outputBase64 = Base64.encodeToString(output, Base64.NO_WRAP);
                Provider provider = thisObj.getProvider();
                String providerName = provider != null ? provider.getName() : "null";
                Log.i(TAG, "\n[*] javax.crypto.Mac.doFinal() onLeave");
                Log.i(TAG, "- algorithm: " + algorithm);
                Log.i(TAG, "- provider: " + providerName);
                Log.i(TAG, "- output(hex): " + toHexString(output));
                Log.i(TAG, "- output(base64): " + outputBase64);
            }
        });


//        testOnce();
    }


    public static void testOnce() {
        try {
            // MD5
            String input = "testmd5input";
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(input.getBytes());
            messageDigest.digest();

            // SHA1
            messageDigest = MessageDigest.getInstance("SHA1");
            messageDigest.update(input.getBytes());
            messageDigest.digest();

            // SHA256
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(input.getBytes());
            messageDigest.digest();

            // AES with key generation
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey aesKey = keyGenerator.generateKey();

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] aesCipher = cipher.doFinal(input.getBytes());

            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            cipher.doFinal(aesCipher);

            // RSA with key generation
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] rsaResult = rsaCipher.doFinal(input.getBytes());
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            rsaCipher.doFinal(rsaResult);

            // RSA sign verify
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(input.getBytes());
            byte[] signResult = signature.sign();

            signature.initVerify(publicKey);
            signature.update(input.getBytes());
            signature.verify(signResult);

            // HMAC
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(aesKey.getEncoded(), "HmacSHA256");
            hmac.init(secretKeySpec);
            hmac.doFinal(input.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
