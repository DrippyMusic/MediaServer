package me.vitormac.mediaserver;

import io.github.cdimascio.dotenv.Dotenv;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

public final class RSAUtils {

    private static PublicKey PUBLIC_KEY;
    private static PrivateKey PRIVATE_KEY;

    static {
        Dotenv dotenv = Dotenv.configure()
                .ignoreIfMissing().load();

        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");

            try (PemReader reader = new PemReader(new FileReader(dotenv.get("PRIVATE_KEY")))) {
                PemObject object = reader.readPemObject();
                PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(object.getContent());

                PRIVATE_KEY = factory.generatePrivate(privKeySpec);
            }

            try (PemReader reader = new PemReader(new FileReader(dotenv.get("PUBLIC_KEY")))) {
                PemObject object = reader.readPemObject();
                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(object.getContent());

                PUBLIC_KEY = factory.generatePublic(pubKeySpec);
            }
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
    }

    private RSAUtils() {
    }

    public static String decrypt(String data) throws IOException {
        if (StringUtils.isEmpty(data)) {
            return StringUtils.EMPTY;
        }

        AsymmetricKeyParameter parameter = PrivateKeyFactory
                .createKey(PRIVATE_KEY.getEncoded());

        AsymmetricBlockCipher cipher = new PKCS1Encoding(new RSAEngine());
        cipher.init(false, parameter);

        try {
            byte[] bytes = Base64.getDecoder().decode(data);
            byte[] block = cipher.processBlock(bytes, 0, bytes.length);
            return new String(block, Charset.defaultCharset());
        } catch (InvalidCipherTextException e) {
            return StringUtils.EMPTY;
        }
    }

    public static String encrypt(String data) throws IOException {
        if (StringUtils.isEmpty(data)) {
            return StringUtils.EMPTY;
        }

        AsymmetricKeyParameter parameter = PublicKeyFactory
                .createKey(PUBLIC_KEY.getEncoded());

        AsymmetricBlockCipher cipher = new PKCS1Encoding(new RSAEngine());
        cipher.init(true, parameter);

        try {
            byte[] block = cipher.processBlock(data.getBytes(), 0, data.length());
            return Base64.getEncoder().encodeToString(block);
        } catch (InvalidCipherTextException e) {
            return StringUtils.EMPTY;
        }
    }

}
