package com.example.licensedemo.utils;

import java.text.SimpleDateFormat;
import java.util.UUID;

/**
 * @Author: LiHuaZhi
 **/
public class UUIDUtils {
    public UUIDUtils() {
    }

    public static String getUuId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    public static String getNumberId() {
        return NumberId.getNumberId();
    }

    public static void main(String[] args) {
        System.out.println(getUuId());
        System.out.println(getNumberId());
    }

    static class NumberId {
        private static int Guid = 100;

        public NumberId() {
        }

        public void main(String[] args) {
            System.out.println(getNumberId());
            System.out.println(getNumberId());
            System.out.println(getNumberId());
        }

        private static String getNumberId() {
            ++Guid;
            long now = System.currentTimeMillis();
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy");
            String time = dateFormat.format(now);
            String info = now + "";
            int ran = 0;
            if (Guid > 999) {
                Guid = 100;
            }

            ran = Guid;
            return time + info.substring(2, info.length()) + ran;
        }
    }
}
