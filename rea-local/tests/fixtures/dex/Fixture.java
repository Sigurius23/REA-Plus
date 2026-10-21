package com.rea.fixture;

public final class Fixture {
  public static final String SECRET = "rea-dex-secret-42";

  public static int checkKey(int key) {
    if (key == 1337) {
      return helper(key) * 2;
    }
    return helper(key) + 1;
  }

  static int helper(int value) {
    return value * 3 + 1;
  }
}
