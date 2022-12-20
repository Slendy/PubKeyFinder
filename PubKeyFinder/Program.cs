using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using PubKeyFinder.Ticket;
using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace PubKeyFinder;

internal static class Program
{
    private static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine($"Usage: {AppDomain.CurrentDomain.FriendlyName} <directory> (name format) (hash override) (curve override)");
            return;
        }
        string[] dir = Directory.GetFiles(args[0], args.Length > 1 ? args[1] : "");
        Console.WriteLine($"Found {dir.Length} files to check");
        var curveCache = new Dictionary<string, ECDomainParameters>();
        var validPoints = new List<ECPoint>();
        string? hashOverride = args.Length > 2 ? (string?)args.GetValue(2) : null;
        string? curveOverride = args.Length > 3 ? (string?)args.GetValue(3) : null;
        if(!string.IsNullOrWhiteSpace(hashOverride)) Console.WriteLine($"Using custom hash function: '{hashOverride}'");
        if(!string.IsNullOrWhiteSpace(curveOverride)) Console.WriteLine($"Using custom curve: '{curveOverride}'");
        foreach (string file in dir)
        {
            byte[] data = File.ReadAllBytes(file);
            NpTicket ticket = NpTicket.FromBytes(data);
            ticket.FileName = Path.GetFileName(file);

            if (!string.IsNullOrWhiteSpace(hashOverride))
            {
                ticket.HashedMessage = NpTicket.ComputeHash(ticket.Message, hashOverride);
                ticket.HashName = hashOverride;
            }

            if (!string.IsNullOrWhiteSpace(curveOverride))
            {
                ticket.CurveName = curveOverride;
            }

            ECDomainParameters curve = curveCache.ContainsKey(ticket.CurveName) ? curveCache[ticket.CurveName] : EcdsaFinder.CurveFromName(ticket.CurveName);
            if(!curveCache.ContainsKey(ticket.CurveName))
                curveCache.Add(ticket.CurveName, curve);

            byte[] sigBackup = ticket.Signature;
            Asn1Sequence? sig = ParseSignature(ticket);

            if (sig is not { Count: 2 })
            {
                Console.WriteLine("signature is invalid");
                Console.WriteLine("sig: " + Convert.ToHexString(ticket.Signature));
                Console.WriteLine("orig sig: " + Convert.ToHexString(sigBackup));
                continue;
            }
            ticket.R = ((DerInteger)sig[0]).PositiveValue;
            ticket.S = ((DerInteger)sig[1]).PositiveValue;

            validPoints.AddRange(EcdsaFinder.RecoverPublicKey(curve, ticket));
        }

        Console.WriteLine($"Valid points: {validPoints.Count}");
        
        var alreadyChecked = new List<ECPoint>();
        foreach (ECPoint p in validPoints)
        {
            if (alreadyChecked.Contains(p)) continue;
            ECPoint normalized = p.Normalize();
            int count = validPoints.Count(x =>
                x.Normalize().AffineXCoord.Equals(normalized.AffineXCoord) &&
                x.Normalize().AffineYCoord.Equals(normalized.AffineYCoord));
            if (count <= 1) continue;
            
            Console.WriteLine("=====");
            Console.WriteLine(normalized.AffineXCoord);
            Console.WriteLine(normalized.AffineYCoord);
            Console.WriteLine($"n={count}");
            Console.WriteLine("=====");
            alreadyChecked.Add(p);
        }

        if (alreadyChecked.Count == 0)
        {
            Console.WriteLine("all points are unique :(");
        }
    }

    private static Asn1Sequence? ParseSignature(NpTicket ticket)
    {
        for (int i = 0; i <= 2; i++)
        {
            try
            {
                Asn1Object.FromByteArray(ticket.Signature);
                break;
            }
            catch
            {
                ticket.Signature = ticket.Signature.SkipLast(1).ToArray();
            }
        }
        Asn1Sequence? sig = (Asn1Sequence?)Asn1Object.FromByteArray(ticket.Signature);
        return sig;
    }

}