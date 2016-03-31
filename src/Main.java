import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/**
 * Created by ibrohim on 3/30/16.
 */
public class Main {

    public static void main(String[] args) {
        ECC engine = new ECC();

        engine.generatePrivateKey();

        Random randomEngine = new Random();
        BigInteger k = new BigInteger(512, randomEngine);
        ECC.Point kB = engine.getB().multiply(k);

        byte[] plaintext = new byte[126];
        new Random().nextBytes(plaintext);

        ECC.Point a = encode(plaintext);
        ECC.Point b = engine.encrypt(k, a);
        ECC.Point c = engine.decrypt(kB, b);

        System.out.println(a.getX());
        System.out.println(a.getY());

        System.out.println(b.getX());
        System.out.println(b.getY());

        System.out.println(c.getX());
        System.out.println(c.getY());

        byte[] decoded = decode(c);

        System.out.println(plaintext.length);
        System.out.println(Arrays.toString(plaintext));
        System.out.println(decoded.length);
        System.out.println(Arrays.toString(decoded));

    }

    public static ECC.Point encode(byte[] plaintext) {
        int byteLength = 64;

        byte[] left = new byte[byteLength];
        byte[] right = new byte[byteLength];

        for (int i=0; i<byteLength-1; i++) left[i+1]  = plaintext[i];
        for (int i=0; i<byteLength-1; i++) right[i+1] = plaintext[i+byteLength-1];

        BigInteger x = new BigInteger(left);
        BigInteger y = new BigInteger(right);

        return new ECC.Point(x,y);
    }

    public static byte[] decode(ECC.Point Q) {
        byte[] xBytes = Q.getX().toByteArray();
        byte[] yBytes = Q.getY().toByteArray();

        byte[] left =  new byte[63];
        byte[] right = new byte[63];

        for (int i=1; i<=63 && i<=xBytes.length; i++) left[63-i]  = xBytes[xBytes.length-i];
        for (int i=1; i<=63 && i<=yBytes.length; i++) right[63-i] = yBytes[yBytes.length-i];

        return concat(left, right);
    }

    public static byte[] concat(byte[] a, byte[] b) {
        int aLen = a.length;
        int bLen = b.length;
        byte[] c= new byte[aLen+bLen];
        System.arraycopy(a, 0, c, 0, aLen);
        System.arraycopy(b, 0, c, aLen, bLen);
        return c;
    }
}
