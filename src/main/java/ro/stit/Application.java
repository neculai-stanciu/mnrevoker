package ro.stit;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.micronaut.runtime.Micronaut;

public class Application {

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Micronaut.run(Application.class);
    }
}
