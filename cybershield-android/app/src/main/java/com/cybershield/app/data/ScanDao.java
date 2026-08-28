package com.cybershield.app.data;

import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

import java.util.List;

@Dao
public interface ScanDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void insert(ScanEntity scan);

    @Query("SELECT * FROM scan ORDER BY createdAt DESC LIMIT 200")
    List<ScanEntity> recent();

    @Query("DELETE FROM scan WHERE createdAt < :cutoff")
    void prune(long cutoff);
}
