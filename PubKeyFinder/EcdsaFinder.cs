using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using PubKeyFinder.Ticket;

namespace PubKeyFinder;

public static class EcdsaFinder
{

    private static ECDomainParameters FromX9EcParams(X9ECParameters param) =>
        new(param.Curve, param.G, param.N, param.H, param.GetSeed());

    public static ECDomainParameters CurveFromName(string name) => FromX9EcParams(ECNamedCurveTable.GetByName(name));
    
    public static IEnumerable<ECPoint> RecoverPublicKey(ECDomainParameters curve, NpTicket ticket)
    {
        var points = new List<ECPoint>();
        for (int i = 0; i < 4; i++)
        {
            try
            {
                ECPoint? p = RecoverPubKey(curve, ticket.R, ticket.S, ticket.HashedMessage, i);
                if (p == null) continue;
                
                ECPublicKeyParameters pubKey = new(p.Normalize(), curve);
                ISigner signer = SignerUtilities.GetSigner(ticket.HashName + "withECDSA");
                signer.Init(false, pubKey);
                signer.BlockUpdate(ticket.Message);
                if (signer.VerifySignature(ticket.Signature))
                {
                    points.Add(p);
                }
            }
            catch
            {
                // ignored
            }
        }

        return points;
    }

    private static ECPoint? RecoverPubKey(ECDomainParameters curveParam, BigInteger r, BigInteger s, byte[] hashedMsg, int j)
    {
        if ((3 & j) != j) {
            Console.WriteLine("The recovery param is more than 2 bits");
        }

        BigInteger n = curveParam.N;
        bool isYOdd = (j & 1) > 0;
        bool isSecondKey = j >> 1 > 0;
        if (r.SignValue <= 0 || r.CompareTo(n) >= 0) {
            Console.WriteLine("Invalid r value");
            return null;
        }
        if (s.SignValue <= 0 || s.CompareTo(n) >= 0) {
            Console.WriteLine("Invalid s value");
            return null;
        }
        
        BigInteger x = isSecondKey ? r.Add(n) : r;
        ECPoint? rPoint = null;
        try
        {
            rPoint = PointFromX(curveParam, x, isYOdd);
        }
        catch
        {
            // ignored
        }

        if (rPoint == null)
        {
            return null;
        }
        
        ECPoint nR = rPoint.Multiply(n);
        if (!nR.Equals(curveParam.Curve.Infinity) || !nR.IsValid()) {
            throw new Exception("nR is not a valid curve point");
        }

        BigInteger rInv = r.ModInverse(n);

        string hex = Convert.ToHexString(hashedMsg);
        BigInteger z = new(hex, 16);
        if(z.BitLength > n.BitLength){
            z = z.ShiftRight(z.BitLength - n.BitLength);
        }
        
        BigInteger s1 = n.Subtract(z).Multiply(rInv).Mod(n);
        BigInteger s2 = s.Multiply(rInv).Mod(n);

        return MultiplyTwo(curveParam, curveParam.G, s1, rPoint, s2);
    }

    private static ECPoint? PointFromX(ECDomainParameters domain, BigInteger x, bool isOdd)
    {
        BigInteger p = domain.Curve.Field.Characteristic;
        BigInteger alpha = x.Pow(3).Add(domain.Curve.A.Multiply(domain.Curve.FromBigInteger(x)).ToBigInteger()).Add(domain.Curve.B.ToBigInteger()).Mod(p);

        BigInteger beta = IntegerFunctions.Ressol(alpha, p);
        
        if(beta.Mod(BigInteger.Two).Equals(BigInteger.Zero) ^ !isOdd){
            beta = p.Subtract(beta); // -y % p
        }
        
        return domain.Curve.CreatePoint(x, beta);
    }
    
    // p * j + x * k
    private static ECPoint MultiplyTwo(ECDomainParameters curve, ECPoint p, BigInteger j, ECPoint x, BigInteger k){
        int i = Math.Max(j.BitLength, k.BitLength) - 1;
        ECPoint r = curve.Curve.Infinity;
        ECPoint both = p.Add(x);

        while (i >= 0) {
            bool jBit = j.TestBit(i);
            bool kBit = k.TestBit(i);

            r = r.Twice();

            if (jBit)
            {
                r = r.Add(kBit ? both : p);
            } else if (kBit) {
                r = r.Add(x);
            }
            --i;
        }

        return r;
    }
}