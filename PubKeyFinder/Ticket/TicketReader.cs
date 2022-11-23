using System.Diagnostics;
using System.Text;

namespace PubKeyFinder.Ticket;

public class TicketReader : BinaryReader
{
    public TicketReader(Stream input) : base(input)
    {}

    public Version ReadTicketVersion() => new((byte)(ReadByte() >> 4), ReadByte());

    public SectionHeader ReadSectionHeader()
    {
        ReadByte();

        SectionHeader sectionHeader = new()
        {
            Type = (SectionType)ReadByte(),
            Length = this.ReadUInt16BE()
        };

        return sectionHeader;
    }

    private DataHeader ReadDataHeader()
    {
        DataHeader dataHeader = new()
        {
            Type = (DataType)this.ReadUInt16BE(),
            Length = this.ReadUInt16BE()
        };

        return dataHeader;
    }

    public byte[] ReadTicketBinary()
    {
        DataHeader dataHeader = this.ReadDataHeader();
        Debug.Assert(dataHeader.Type is DataType.Binary or DataType.String);

        return this.ReadBytes(dataHeader.Length);
    }

    public string ReadTicketString() => Encoding.UTF8.GetString(this.ReadTicketBinary()).TrimEnd('\0');

    public uint ReadTicketUInt32()
    {
        DataHeader dataHeader = this.ReadDataHeader();
        Debug.Assert(dataHeader.Type == DataType.UInt32);

        return this.ReadUInt32BE();
    }
    
    public void ReadTicketEmpty()
    {
        DataHeader dataHeader = this.ReadDataHeader();
        Debug.Assert(dataHeader.Type == DataType.Empty);
    }


    public ulong ReadTicketUInt64()
    {
        DataHeader dataHeader = this.ReadDataHeader();
        Debug.Assert(dataHeader.Type is DataType.UInt64 or DataType.Timestamp);

        return this.ReadUInt64BE();
    }
}