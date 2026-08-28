# Keep Gson DTOs (fields are populated by reflection)
-keep class com.cybershield.app.net.dto.** { *; }

# Retrofit / OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn retrofit2.**
-keepattributes Signature, RuntimeVisibleAnnotations, AnnotationDefault

# Room
-keep class * extends androidx.room.RoomDatabase { *; }
-dontwarn androidx.room.paging.**
