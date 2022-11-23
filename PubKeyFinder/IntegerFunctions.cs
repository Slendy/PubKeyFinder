using Org.BouncyCastle.Math;

namespace PubKeyFinder;

public static class IntegerFunctions
{
    private static readonly BigInteger ZERO = BigInteger.Zero;

    private static readonly BigInteger ONE = BigInteger.One;

    private static readonly BigInteger TWO = BigInteger.Two;

    private static readonly BigInteger FOUR = BigInteger.Four;

    // the jacobi function uses this lookup table
    private static readonly int[] jacobiTable = { 0, 1, 0, -1, 0, -1, 0, 1 };

    // Computes the value of the Jacobi symbol (A|B). The following properties
    // hold for the Jacobi symbol which makes it a very efficient way to
    // evaluate the Legendre symbol
    // <p>
    // (A|B) = 0 IF gcd(A,B) &gt; 1<br>
    // (-1|B) = 1 IF n = 1 (mod 1)<br>
    // -1|B) = -1 IF n = 3 (mod 4)<br>
    // (A|B) (C|B) = (AC|B)<br>
    // (A|B) (A|C) = (A|CB)<br>
    // (A|B) = (C|B) IF A = C (mod B)<br>
    // (2|B) = 1 IF N = 1 OR 7 (mod 8)<br>
    // (2|B) = 1 IF N = 3 OR 5 (mod 8)
    //
    // @param A integer value
    // @param B integer value
    // @return value of the jacobi symbol (A|B)
    //
    public static int jacobi(BigInteger A, BigInteger B)
    {
        BigInteger a, b, v;
        long k = 1;

        k = 1;

        // test trivial cases
        if (B.Equals(ZERO))
        {
            a = A.Abs();
            return a.Equals(ONE) ? 1 : 0;
        }

        if (!A.TestBit(0) && !B.TestBit(0))
        {
            return 0;
        }

        a = A;
        b = B;

        if (b.SignValue == -1)
        {
            // b < 0
            b = b.Negate(); // b = -b
            if (a.SignValue == -1)
            {
                k = -1;
            }
        }

        v = ZERO;
        while (!b.TestBit(0))
        {
            v = v.Add(ONE); // v = v + 1
            b = b.Divide(TWO); // b = b/2
        }

        if (v.TestBit(0))
        {
            k = k * jacobiTable[a.IntValue & 7];
        }

        if (a.SignValue < 0)
        {
            // a < 0
            if (b.TestBit(1))
            {
                k = -k; // k = -k
            }

            a = a.Negate(); // a = -a
        }

        // main loop
        while (a.SignValue != 0)
        {
            v = ZERO;
            while (!a.TestBit(0))
            {
                // a is even
                v = v.Add(ONE);
                a = a.Divide(TWO);
            }

            if (v.TestBit(0))
            {
                k = k * jacobiTable[b.IntValue & 7];
            }

            if (a.CompareTo(b) < 0)
            {
                // a < b
                // swap and correct intermediate result
                (a, b) = (b, a);
                if (a.TestBit(1) && b.TestBit(1))
                {
                    k = -k;
                }
            }

            a = a.Subtract(b);
        }

        return b.Equals(ONE) ? (int)k : 0;
    }

    /**
     * Computes the square root of a BigInteger modulo a prime employing the
     * Shanks-Tonelli algorithm.
     *
     * @param a value out of which we extract the square root
     * @param p prime modulus that determines the underlying field
     * @return a number <tt>b</tt> such that b<sup>2</sup> = a (mod p) if
     *         <tt>a</tt> is a quadratic residue modulo <tt>p</tt>.
     * @throws IllegalArgumentException if <tt>a</tt> is a quadratic non-residue modulo <tt>p</tt>
     */
    public static BigInteger Ressol(BigInteger a, BigInteger p)
    {
        BigInteger v;

        if (a.CompareTo(ZERO) < 0)
        {
            a = a.Add(p);
        }

        if (a.Equals(ZERO))
        {
            return ZERO;
        }

        if (p.Equals(TWO))
        {
            return a;
        }

        // p = 3 mod 4
        if (p.TestBit(0) && p.TestBit(1))
        {
            if (jacobi(a, p) == 1)
            {
                // a quadr. residue mod p
                v = p.Add(ONE); // v = p+1
                v = v.ShiftRight(2); // v = v/4
                return a.ModPow(v, p); // return a^v mod p
                // return --> a^((p+1)/4) mod p
            }

            throw new ArgumentException("No quadratic residue: " + a + ", " + p);
        }

        long t = 0;

        // initialization
        // compute k and s, where p = 2^s (2k+1) +1

        BigInteger k = p.Subtract(ONE); // k = p-1
        long s = 0;
        while (!k.TestBit(0))
        {
            // while k is even
            s++; // s = s+1
            k = k.ShiftRight(1); // k = k/2
        }

        k = k.Subtract(ONE); // k = k - 1
        k = k.ShiftRight(1); // k = k/2

        // initial values
        BigInteger r = a.ModPow(k, p); // r = a^k mod p

        BigInteger n = r.Multiply(r).Remainder(p); // n = r^2 % p
        n = n.Multiply(a).Remainder(p); // n = n * a % p
        r = r.Multiply(a).Remainder(p); // r = r * a %p

        if (n.Equals(ONE))
        {
            return r;
        }

        // non-quadratic residue
        BigInteger z = TWO; // z = 2
        while (jacobi(z, p) == 1)
        {
            // while z quadratic residue
            z = z.Add(ONE); // z = z + 1
        }

        v = k;
        v = v.Multiply(TWO); // v = 2k
        v = v.Add(ONE); // v = 2k + 1
        BigInteger c = z.ModPow(v, p); // c = z^v mod p

        // iteration
        while (n.CompareTo(ONE) == 1)
        {
            // n > 1
            k = n; // k = n
            t = s; // t = s
            s = 0;

            while (!k.Equals(ONE))
            {
                // k != 1
                k = k.Multiply(k).Mod(p); // k = k^2 % p
                s++; // s = s + 1
            }

            t -= s; // t = t - s
            if (t == 0)
            {
                throw new ArgumentException("No quadratic residue: " + a + ", " + p);
            }

            v = ONE;
            for (long i = 0; i < t - 1; i++)
            {
                v = v.ShiftLeft(1); // v = 1 * 2^(t - 1)
            }

            c = c.ModPow(v, p); // c = c^v mod p
            r = r.Multiply(c).Remainder(p); // r = r * c % p
            c = c.Multiply(c).Remainder(p); // c = c^2 % p
            n = n.Multiply(c).Mod(p); // n = n * c % p
        }

        return r;
    }
}