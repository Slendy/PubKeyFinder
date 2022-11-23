using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;

namespace PubKeyFinder.Ticket;

public class NpTicket
{
    public byte[] Signature { get; set; } = Array.Empty<byte>();
    public byte[] Message { get; set; } = Array.Empty<byte>();
    public byte[] HashedMessage { get; set; } = Array.Empty<byte>();
    public string HashName { get; set; } = "";
    public string CurveName { get; set; } = "";
    public BigInteger R { get; set; } = BigInteger.Zero;
    public BigInteger S { get; set; } = BigInteger.Zero;
    public string FileName { get; set; } = "";

    public static NpTicket FromBytes(byte[] data)
    {
        NpTicket ticket = new();
        MemoryStream ms = new(data);
        TicketReader reader = new(ms);
        Version version = reader.ReadTicketVersion();
        reader.ReadBytes(4);
        reader.ReadUInt16BE(); // ticket len

        long bodyStart = reader.BaseStream.Position;

        SectionHeader bodyHeader = reader.ReadSectionHeader();
        ticket.Message = data.AsSpan((int)bodyStart, bodyHeader.Length + 4).ToArray();
        
        reader.ReadTicketString(); // "Serial id", but its apparently not what we're looking for

        reader.ReadTicketUInt32(); // issuerid
        reader.ReadTicketUInt64(); // issueddate
        reader.ReadTicketUInt64(); // expiredate

        reader.ReadTicketUInt64(); // PSN User id, we don't care about this

        reader.ReadTicketString(); // username

        reader.ReadTicketString(); // Country
        reader.ReadTicketString(); // Domain

        reader.ReadTicketString(); // titleid

        reader.ReadTicketUInt32(); // status

        reader.ReadTicketEmpty(); // padding
        reader.ReadTicketEmpty();

        reader.ReadSectionHeader(); // footer header

        reader.ReadTicketBinary(); // 4 byte identifier (cipher id?)

        ticket.Signature = reader.ReadTicketBinary();

        if (ticket.Signature.Length == 56)
        {
            ticket.HashedMessage = SHA1.Create().ComputeHash(ticket.Message);
            ticket.HashName = "SHA1";
            ticket.CurveName = "secp192k1";
        }
        else
        {
            ticket.HashedMessage = ComputeSha224Hash(ticket.Message);
            ticket.HashName = "SHA224";
            ticket.CurveName = "secp224k1";
        }

        return ticket;
    }

    public static byte[] ComputeHash(byte[] data, string hashName)
    {
        return hashName switch
        {
            "SHA1" => SHA1.Create().ComputeHash(data),
            "SHA224" => ComputeSha224Hash(data),
            _ => HashAlgorithm.Create(hashName)?.ComputeHash(data) ?? Array.Empty<byte>(),
        };
    }

    private static byte[] ComputeSha224Hash(byte[] data)
    {
        Sha224Digest digest = new();
        digest.BlockUpdate(data, 0, data.Length);
        byte[] hashBuf = new byte[digest.GetDigestSize()];
        digest.DoFinal(hashBuf, 0);
        return hashBuf;
    }
}