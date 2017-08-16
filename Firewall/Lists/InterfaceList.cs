using System.Collections.Generic;
using Firewall.Nodes;

namespace Firewall.Lists
{
    public class InterfaceList
    {
        private List<InterfaceNode> InterfaceNodes { get; }

        public InterfaceList()
        {
            InterfaceNodes = new List<InterfaceNode>();
        }

        public void Add(InterfaceNode node)
        {
            InterfaceNodes.Add(node);
        }
    }
}