package me.vitormac.mediaserver;

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

public final class RSAUtils {

    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public RSAUtils(String pub, String priv) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        this.publicKey = RSAUtils.getPublicKey(pub);
        this.privateKey = RSAUtils.getPrivateKey(priv);
    }

    public final String decrypt(String data) throws IOException {
        if (StringUtils.isEmpty(data)) {
            return StringUtils.EMPTY;
        }

        AsymmetricKeyParameter parameter = PrivateKeyFactory
                .createKey(this.privateKey.getEncoded());

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

    public final String encrypt(String data) throws IOException {
        if (StringUtils.isEmpty(data)) {
            return StringUtils.EMPTY;
        }

        AsymmetricKeyParameter parameter = PublicKeyFactory
                .createKey(this.publicKey.getEncoded());

        AsymmetricBlockCipher cipher = new PKCS1Encoding(new RSAEngine());
        cipher.init(true, parameter);

        try {
            byte[] block = cipher.processBlock(data.getBytes(), 0, data.length());
            return Base64.getEncoder().encodeToString(block);
        } catch (InvalidCipherTextException e) {
            return StringUtils.EMPTY;
        }
    }

    public static PublicKey getPublicKey(String path)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        try (PemReader reader = new PemReader(new FileReader(path))) {
            PemObject object = reader.readPemObject();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(object.getContent());

            return factory.generatePublic(spec);
        }
    }

    public static PrivateKey getPrivateKey(String path)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory factory = KeyFactory.getInstance("RSA");

        try (PemReader reader = new PemReader(new FileReader(path))) {
            PemObject object = reader.readPemObject();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(object.getContent());

            return factory.generatePrivate(spec);
        }
    }

}
