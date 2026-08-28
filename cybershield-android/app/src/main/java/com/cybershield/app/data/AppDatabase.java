package com.cybershield.app.data;

import android.content.Context;

import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;

@Database(entities = {ScanEntity.class, BlockedIndicator.class}, version = 1, exportSchema = false)
public abstract class AppDatabase extends RoomDatabase {

    public abstract ScanDao scanDao();
    public abstract BlocklistDao blocklistDao();

    private static volatile AppDatabase INSTANCE;

    public static AppDatabase create(Context ctx) {
        INSTANCE = Room.databaseBuilder(ctx.getApplicationContext(), AppDatabase.class, "cybershield.db")
                .fallbackToDestructiveMigration()
                .allowMainThreadQueries()   // queries are tiny key lookups; keeps the shield synchronous
                .build();
        return INSTANCE;
    }

    public static AppDatabase get(Context ctx) {
        if (INSTANCE == null) {
            synchronized (AppDatabase.class) {
                if (INSTANCE == null) create(ctx);
            }
        }
        return INSTANCE;
    }
}
