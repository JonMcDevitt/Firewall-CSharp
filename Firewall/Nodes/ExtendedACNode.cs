namespace Firewall.Nodes
{
    public class ExtendedACNode : ACNode
    {
        private string Protocol { get; }
        private string DestIP { get; }
        private string DestMask { get; }
        private string DestPort { get; }

        public ExtendedACNode(string accessList, string groupNumber, bool access, string srcIpAddress, string srcMask, string protocol, string destIP, string destMask, string destPort) 
            : base(accessList, groupNumber, access, srcIpAddress, srcMask)
        {
            Protocol = protocol;
            DestIP = destIP;
            DestMask = destMask;
            DestPort = destPort;
        }

        public bool CheckDest(string ip)
        {
            return CheckSource(ip, DestIP, DestMask);
        }

        public override string ToString()
        {
            var msg = "";

            msg += AccessList + "\t";
            msg += GroupNumber + "\t";
            msg += (Access ? "permit" : "deny") + "\t";
            msg += Protocol + "\t";
            msg += SrcIp + "\t";
            msg += SrcMask + "\t";
            msg += DestIP + "\t";
            msg += DestMask + "\t";
            msg += DestPort + "\n";

            return msg;
        }
    }
}