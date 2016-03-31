import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/**
 * Created by ibrohim on 3/30/16.
 */
public class Main {

    public static void main(String[] args) {
        ECC engine = new ECC();

        Random randomEngine = new Random();

        engine.generatePrivateKey();

        BigInteger BigPlainText = new BigInteger(1008, randomEngine);
        BigInteger k = new BigInteger(512, randomEngine);

        ECC.Point kB = engine.getB().multiply(k);

        int byteLength = 128;

        byte[] plaintext = BigPlainText.toByteArray();

        System.out.println(plaintext.length);

        byte[] expandedPlainText = new byte[byteLength];
        int padding = byteLength - plaintext.length;

        for (int i=0; i<plaintext.length; i++) expandedPlainText[i+padding] = plaintext[i];

        ECC.Point a = engine.encode(expandedPlainText);

        ECC.Point b = engine.encrypt(k, a);

        ECC.Point c = engine.decrypt(kB, b);

        System.out.println(a.getX());
        System.out.println(a.getY());

        System.out.println(b.getX());
        System.out.println(b.getY());

        System.out.println(c.getX());
        System.out.println(c.getY());

        byte[] decoded = engine.decode(c);

        System.out.println(Arrays.toString(plaintext));
        System.out.println(Arrays.toString(decoded));

    }
}
