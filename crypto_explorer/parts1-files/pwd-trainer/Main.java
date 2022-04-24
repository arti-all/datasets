package com.github.t1.pwdtrainer;

import java.io.Console;
import java.security.*;
import java.util.Arrays;

public class Main {
    private static final String BELL = "\07";

    public static void main(String[] args) {
        Console console = System.console();
        if (console == null) {
            System.err.println("no console available to read passwords from");
        } else {
            new Main(console).run();
        }
    }

    private final Console console;
    private final byte[] digest;

    private Main(Console console) {
        this.console = console;
        this.digest = read("please initialize your password: ");
    }

    private void run() {
        for (int i = 0; i < 1000; i++) {
            long t0 = System.currentTimeMillis();
            byte[] next = read("try " + i + ": ");
            if (next == null)
                break;
            long t = System.currentTimeMillis() - t0;
            if (Arrays.equals(next, digest)) {
                System.out.println("matched.    took " + t + "ms");
            } else {
                System.out.println(BELL + "WRONG!!!    took " + t + "ms");
            }
        }
        System.out.println("\nThanks!");
    }

    private byte[] read(String message) {
        char[] c = console.readPassword(message);
        if (c == null || c.length == 0)
            return null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA");
            return md.digest(new String(c).getBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
