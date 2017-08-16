namespace Firewall.Nodes
{
    public class InterfaceNode
    {
        private string InterfaceID { get; set; }

        public InterfaceNode(string id)
        {
            InterfaceID = id;
        }

        public override string ToString()
        {
            return "interface\t" + InterfaceID + "\n";
        }
    }
}