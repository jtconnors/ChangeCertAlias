/*
 * Copyright (c) 2018, Jim Connors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of this project nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.jtconnors.keystoreutil;

import java.io.Console;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;

/**
 * Programmatically modify a Java KeyStore alias with characters that are not
 * friendly to Windows CMD shell.
 *
 * See SAMPLE_RUN.txt to see how to try a sample run.
 */
public class ChangeCertAlias {

    private static String selectedAlias;

    private static Console GetConsole() {
        Console cons = System.console();
        if (cons == null) {
            throw new RuntimeException("Can't get Console");
        }
        return cons;
    }

    private static void PrintAliases(List<String> aliasList,
            String keystoreName) {
        if (!aliasList.isEmpty()) {
            int index = 0;
            System.out.println("");
            System.out.println("Aliases in " + keystoreName);
            for (String alias : aliasList) {
                System.out.println("\t" + ++index + ": " + alias);
            }
        }
    }

    private static String SelectAlias(List<String> aliasList,
            String keystoreName) {
        int aliasIndex = 0;
        boolean done = false;
        PrintAliases(aliasList, keystoreName);
        do {
            String input = GetConsole().
                        readLine("%s", "Select an alias number: ");
            try {
                aliasIndex = Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.out.println("Non-numeric input, input a number");
                continue;
            }
            if (aliasIndex > 0 && aliasIndex <= aliasList.size()) {
                done = true;
            } else {
                System.out.println("Number must be > 0 and <= " + 
                        aliasList.size());
            }
        } while (!done);
        return aliasList.get(aliasIndex - 1);
    }

    public static void main(String[] args) {
        try {
            System.out.println("");
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

            // Prompt for the original keystore file
            String keystoreName
                  = GetConsole().readLine("%s", "Keystore file: ");

            // Get the keystore Password from the console, disabling
            // character echo.  Note: this will not work inside NetBeans
            char[] keystorePasswd = GetConsole().readPassword(
                    "%s", "Enter keystore password: ");

            // Open the original keystore
            try (FileInputStream fis = new FileInputStream(keystoreName)) {
                ks.load(fis, keystorePasswd);
            }

            // Present the user with the list of aliases in the keystore and
            // prompt to choose one.
            List<String> aliasList = Collections.list(ks.aliases());
            if (!aliasList.isEmpty()) {
                selectedAlias = SelectAlias(aliasList, keystoreName);
            } else {
                System.out.println("No aliases found in keystore: "
                        + keystoreName + " - exiting.");
                System.exit(1);
            }

            // Open the keystore and search for the alias represented by
            // selectedAlias.  If not successful, exit.
            if (!ks.containsAlias(selectedAlias)) {
                System.out.println("alias: " + "\"" + selectedAlias + "\""
                        + " NOT FOUND in keystore.  No modifications made.");
                System.exit(1);
            }

            // Prompt for the value of the new alias which will replace
            // the original selected alias
            String newAliasStr = GetConsole().readLine(
                    "%s", "Enter the new certificate alias: ");

            // Prompt for the name of the new keystore file 
            String newKeystoreName = GetConsole().readLine(
                    "%s", "Name of new keystore file: ");
            if (newKeystoreName.equals(keystoreName)) {
                System.out.println("new keystore file: " + newKeystoreName
                        + " cannot be identical to original keystore: "
                        + keystoreName + " Exiting.");
                System.exit(1);
            }

            // Get the key password from the console, disabling
            // character echo.  Note: this will not work inside NetBeans
            char[] keyPasswd
                    = GetConsole().readPassword("%s", "Enter key password: ");

            // Replace the certificate chain matching the original selectedAlias
            // with the new alias that the user supplied 
            Certificate[] certChain = ks.getCertificateChain(selectedAlias);
            Key key = ks.getKey(selectedAlias, keyPasswd);
            ks.deleteEntry(selectedAlias);
            ks.setKeyEntry(newAliasStr, key, keyPasswd, certChain);
            try (FileOutputStream fos = new FileOutputStream(newKeystoreName)) {
                ks.store(fos, keystorePasswd);
            }

            System.out.println("New keystore: " + newKeystoreName
                    + " created with updated alias: " + "\"" + newAliasStr + "\"");
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException |
                UnrecoverableKeyException | CertificateException e) {
            e.printStackTrace();
        }
    }
}

