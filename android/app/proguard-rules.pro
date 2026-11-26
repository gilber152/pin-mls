# Conservar clases JNI/JNA generadas por UniFFI
-keep class uniffi.pin_mobile_ffi.** { *; }
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
