package com.cybershield.app.data;

import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

import java.util.List;

@Dao
public interface BlocklistDao {

    @Query("SELECT EXISTS(SELECT 1 FROM blocked WHERE type = :type AND value = :value)")
    boolean isBlocked(String type, String value);

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void upsertAll(List<BlockedIndicator> items);

    @Query("DELETE FROM blocked")
    void clear();

    @Query("SELECT COUNT(*) FROM blocked")
    int count();
}
