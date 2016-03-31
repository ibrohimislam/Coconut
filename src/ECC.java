import com.sun.deploy.util.ArrayUtil;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/**
 * Created by ibrohim on 3/30/16.
 */

public class ECC {

    final public static int LENGTH = 512;

    final private static BigInteger prime = new BigInteger("10689075161139667223042978873670922480965002748064399240516442267332455939465850789168580996329723390343748361862365528184970115449827990155533456897223667");
    final private static BigInteger a = new BigInteger("1");

    final private static BigInteger TWO = new BigInteger("2");
    final private static BigInteger THREE = new BigInteger("3");
    final private static BigInteger FOUR = new BigInteger("4");

    final private static Point randomBase = new Point(TWO,FOUR);

    private BigInteger p; // Private Key
    private Point B; // Base
    private Point Q; // Public Key

    public ECC(){}

    public void setPublicKey(BigInteger Bx, BigInteger By, BigInteger Qx, BigInteger Qy){
        Q = new Point(Qx,Qy);
        B = new Point(Bx,By);
    }

    public void setPrivateKey(BigInteger Bx, BigInteger By, BigInteger P){
        p = P;
        B = new Point(Bx,By);
        Q = B.multiply(p);
    }

    public Point getB(){
        return B;
    }

    public Point encrypt(BigInteger k, Point plaintext){
        Point kPb = Q.multiply(k);

        Point encodedCipherText = plaintext.add(kPb);

        return encodedCipherText;
    }

    public Point decrypt(Point kB, Point ciphertext){

        Point key = kB.multiply(p).negate();

        Point encodedPlainText = ciphertext.add(key);

        return encodedPlainText;
    }

    public void generatePrivateKey(){

        Random randomEngine = new Random();

        B = generateRandomPoint();

        p = new BigInteger(512,randomEngine);

        Q = B.multiply(p);

    }

    public Point generateRandomPoint(){

        Random randomEngine = new Random();

        BigInteger k = new BigInteger(512,randomEngine);

        return randomBase.multiply(k);
    }

    public static class Point{

        final public static Point O = new Point(BigInteger.ZERO,BigInteger.ZERO);

        BigInteger x;
        BigInteger y;

        public Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        public BigInteger getX() { return x; }
        public BigInteger getY() { return y; }

        public Point add(Point other){

            if (this.equals(O)) return other;
            else if (other.equals(O)) return this;

            BigInteger x1 = getX();
            BigInteger x2 = other.getX();
            BigInteger dx = x1.subtract(x2);
            BigInteger y1 = getY();
            BigInteger y2 = other.getY();
            BigInteger dy = y1.subtract(y2);

            BigInteger dx_inverse = dx.modInverse(ECC.prime);

            BigInteger lambda = dy.multiply(dx_inverse).mod(ECC.prime);

            BigInteger xr = lambda.multiply(lambda).subtract(x1).subtract(x2).mod(ECC.prime);

            BigInteger temp = x1.subtract(xr);
            BigInteger yr = lambda.multiply(temp).subtract(y1).mod(ECC.prime);

            return new Point(xr,yr);
        }

        public Point multiply2(){
            BigInteger x = getX();
            BigInteger y = getY();

            BigInteger dx = x.multiply(x).multiply(THREE).add(a).mod(prime);
            BigInteger dy_inverse = y.shiftLeft(1).modInverse(prime);

            BigInteger lambda = dx.multiply(dy_inverse).mod(ECC.prime);

            BigInteger xr = lambda.multiply(lambda).subtract(x.shiftLeft(1)).mod(ECC.prime);

            BigInteger temp = x.subtract(xr);
            BigInteger yr = lambda.multiply(temp).subtract(y).mod(ECC.prime);

            return new Point(xr,yr);
        }

        public Point multiply(BigInteger k){
            Point temp = this;
            Point answer = O;

            while(k.signum() == 1) {
                if (k.mod(TWO).signum() == 1) answer = answer.add(temp);
                k = k.shiftRight(1);
                temp = temp.multiply2();
            }

            return answer;
        }

        public Point negate(){
            return new Point(x,y.negate());
        }
    }

}
