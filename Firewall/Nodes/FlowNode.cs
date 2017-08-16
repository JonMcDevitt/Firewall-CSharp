namespace Firewall.Nodes
{
    public class FlowNode
    {
        private string IP { get; set; }
        private string AccessGroup { get; set; }
        private string GroupNum { get; set; }
        private string FlowDir { get; set; } /* The direction on which the ACL prevents traffic. */

        public FlowNode(string ip, string groupNum, string flowDir)
        {
            IP = ip;
            AccessGroup = "access-group";
            GroupNum = groupNum;
            FlowDir = flowDir;
        }

        public override string ToString()
        {
            var msg = "";

            msg += IP + "\t";
            msg += AccessGroup + "\t";
            msg += GroupNum + "\t";
            msg += FlowDir + "\n";

            return msg;
        }
    }
}